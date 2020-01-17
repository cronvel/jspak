/*
	JsPak

	Copyright (c) 2020 Cédric Ronvel

	The MIT License (MIT)

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
*/

"use strict" ;



/*
	Support per file/data:
		- gzip compression
		- encryption (aes-256-ctr + per file random init vector)

	Other features:
		- Being able to hijack require(), so requiring JS inside the archive is possible, and get priority over local files
		  starting at the directory where the archive lies (may be configurable).
		- Support multiple files with a number scheme, the later superseding existing files (e.g. like Q3 pak0.pak, pak1.pak, ...),
		  allowing distribution of extension pack/patch.
*/

/*
	TODO:
		- manage directories (can create empty directories, and set mode, mtime, etc)
		- delete/replace
*/


const cryptoHelper = require( './cryptoHelper.js' ) ;

const Promise = require( 'seventh' ) ;

const path = require( 'path' ) ;
const fs = require( 'fs' ) ;
const fsKit = require( 'fs-kit' ) ;
const streamKit = require( 'stream-kit' ) ;
const zlib = require( 'zlib' ) ;
const gunzipBuffer = Promise.promisify( zlib.gunzip ) ;

const log = require( 'logfella' ).global.use( 'JsPak' ) ;



function JsPak( filePath , options = {} ) {
	this.filePath = filePath ;
	this.file = null ;
	this.isNew = null ;			// True if the archive was created, false if it existed
	this.loaded = false ;		// True if the file header and index are loaded
	this.eof = null ;			// End Of File offset
	this.indexMap = new Map() ;
	this.directoryMap = new Map() ;
	this.encryptionKey = options.encryptionKey || '' ;
}

module.exports = JsPak ;



// Open the file
JsPak.prototype.open = async function( shouldBeNew = null ) {
	if ( this.file ) { return ; }

	try {
		this.file = await fs.promises.open( this.filePath , 'r+' ) ;
		if ( shouldBeNew === true ) { throw new Error( 'Expected ' + this.filePath + ' to not exist!' ) ; }
		let stats = await this.file.stat() ;
		this.eof = stats.size ;
		this.isNew = false ;
	}
	catch ( error ) {
		if ( error.code === 'ENOENT' ) {
			if ( shouldBeNew === false ) { throw new Error( 'Expected ' + this.filePath + ' to exist!' ) ; }
			this.file = await fs.promises.open( this.filePath , 'w+' ) ;
			this.file.write( 'JPK' ) ;
			this.loaded = true ;
			this.eof = 3 ;
			this.isNew = true ;
			return ;
		}

		throw error ;
	}

	if ( this.eof < 3 ) {
		throw new Error( "Not a JPK file (too small)" ) ;
	}

	var magicBuffer = Buffer.allocUnsafe( 3 ) ;
	await this.file.read( magicBuffer , 0 , 3 ) ;
	if ( magicBuffer.toString( 'utf8' ) !== 'JPK' ) {
		throw new Error( "Not a JPK file (bad magic bytes)" ) ;
	}
} ;



JsPak.prototype.load = async function() {
	var buffer , position , flags , type , index , directory , dataBlockSize ;

	if ( this.loaded ) { return ; }
	if ( ! this.file ) { await this.open() ; }

	if ( this.eof <= 3 ) {
		this.loaded = true ;
		return ;
	}

	buffer = Buffer.allocUnsafe( Math.max( INDEX_MAX_SIZE , DIRECTORY_MAX_SIZE ) ) ;
	position = 3 ;

	while ( position < this.eof ) {
		//log.hdebug( "bloc position: %i" , position ) ;
		await this.file.read( buffer , 0 , 1 , position ++ ) ;
		flags = buffer.readUInt8( 0 ) ;
		//log.hdebug( "flags: %i" , flags ) ;
		type = flags & MASK_TYPE ;

		if ( type === FLAG_TYPE_INDEX ) {
			//log.hdebug( "position: %i" , position ) ;
			await this.file.read( buffer , 1 , INDEX_FIXED_SIZE - 1 , position ) ;
			position += INDEX_FIXED_SIZE - 1 ;
			//log.hdebug( "buffer: %n" , buffer ) ;

			index = {} ;
			index.offset = buffer.readUInt32BE( 1 ) ;
			index.size = buffer.readUInt32BE( 5 ) ;
			index.mode = buffer.readUInt16BE( 9 ) ;
			index.mtime = new Date( buffer.readDoubleBE( 11 ) ) ;
			index.atime = new Date( buffer.readDoubleBE( 19 ) ) ;
			index.keySize = buffer.readUInt8( 27 ) ;
			index.gzip = flags & FLAG_GZIP ;
			index.encryption = flags & FLAG_ENCRYPTION ;

			await this.file.read( buffer , INDEX_FIXED_SIZE , index.keySize , position ) ;
			position += index.keySize ;
			index.key = buffer.toString( 'utf8' , INDEX_FIXED_SIZE , INDEX_FIXED_SIZE + index.keySize ) ;

			this.indexMap.set( index.key , index ) ;
			log.hdebug( "Index: %Y" , index ) ;
		}
		else if ( type === FLAG_TYPE_DIRECTORY ) {
			//log.hdebug( "position: %i" , position ) ;
			await this.file.read( buffer , 1 , DIRECTORY_FIXED_SIZE - 1 , position ) ;
			position += DIRECTORY_FIXED_SIZE - 1 ;
			//log.hdebug( "buffer: %n" , buffer ) ;

			directory = {} ;
			directory.mode = buffer.readUInt16BE( 1 ) ;
			directory.mtime = new Date( buffer.readDoubleBE( 3 ) ) ;
			directory.atime = new Date( buffer.readDoubleBE( 11 ) ) ;
			directory.keySize = buffer.readUInt8( 19 ) ;

			await this.file.read( buffer , DIRECTORY_FIXED_SIZE , directory.keySize , position ) ;
			position += directory.keySize ;
			directory.key = buffer.toString( 'utf8' , DIRECTORY_FIXED_SIZE , DIRECTORY_FIXED_SIZE + directory.keySize ) ;

			this.directoryMap.set( directory.key , directory ) ;
			log.hdebug( "Directory: %Y" , directory ) ;
		}
		//else if ( type === FLAG_TYPE_HEADER ) {}
		else if ( type === FLAG_TYPE_DATABLOCK ) {
			// This is a datablock: skip it!
			await this.file.read( buffer , 1 , DATABLOCK_FIXED_SIZE - 1 , position ) ;
			position += DATABLOCK_FIXED_SIZE - 1 ;
			dataBlockSize = buffer.readUInt32BE( 1 ) ;
			position += dataBlockSize ;
			log.hdebug( "Skipping Data Block of size: %iB" , dataBlockSize ) ;
		}

		//log.hdebug( "loop -- pos: %i , eof: %i" , position , this.eof ) ;
	}

	this.loaded = true ;
	return ;
} ;



JsPak.prototype.add = async function( files , options = {} ) {
	if ( ! this.loaded ) { await this.load() ; }

	if ( ! Array.isArray( files ) ) { files = [ files ] ; }

	// Check options.prefix, it should not be absolute, and should not contains ../ ~/
	if ( options.prefix ) {
		if ( path.isAbsolute( options.prefix ) || options.prefix.includes( '../' ) || options.prefix.includes( '~/' ) ) {
			throw new Error( "Bad prefix '" + options.prefix + "', it should not be absolute or contains ../ or ~/" ) ;
		}
	}

	var key , keys = [] , directoryKeys = [] , keySize , flags , gzip , encryption , mode , mtime , atime ,
		file , filePath , fileName , prefix , stats , children ,
		dataBlockOffset , dataBlockSize ,
		directory , directorySize , directoryBuffer ,
		index , indexSize , dataOffset = 0 , dataSize = 0 ,
		indexBuffer , dataBlockHeaderBuffer ,
		inputFile , inputStream , outputStream , middleStreams ;

	dataBlockHeaderBuffer = Buffer.allocUnsafe( DATABLOCK_FIXED_SIZE ) ;
	directoryBuffer = indexBuffer = Buffer.allocUnsafe( Math.max( INDEX_MAX_SIZE , DIRECTORY_MAX_SIZE ) ) ;


	// First write the data block flags and size
	dataBlockOffset = this.eof ;
	dataBlockSize = 0 ;
	flags = FLAG_TYPE_DATABLOCK ;
	dataBlockHeaderBuffer.writeUInt8( flags , 0 ) ;
	dataBlockHeaderBuffer.writeUInt32BE( 0 , 1 ) ;	// reserve space for the datablock size
	await this.file.write( dataBlockHeaderBuffer , 0 , DATABLOCK_FIXED_SIZE , this.eof ) ;
	this.eof += DATABLOCK_FIXED_SIZE ;


	// Now write each file and collect informations
	for ( file of files ) {
		if ( typeof file === 'string' ) { file = { filePath: file } ; }

		inputFile = filePath = fileName = null ;
		prefix = file.prefix || '' ;
		gzip = file.gzip !== undefined ? file.gzip : !! options.gzip ;
		encryption = file.encryption !== undefined ? file.encryption : !! options.encryption ;

		if ( file.filePath ) {
			// This is a file
			filePath = file.filePath ;
			fileName = path.basename( filePath ) ;
			key = path.join( options.prefix || '' , prefix , fileName ) ;
			keySize = Buffer.byteLength( key ) ;
			if ( keySize > 255 ) { throw new Error( 'Key too large: ' + key ) ; }

			inputFile = await fs.promises.open( filePath , 'r' ) ;
			stats = await inputFile.stat() ;

			mode = file.mode !== undefined ? file.mode : stats.mode ;
			mtime = file.mtime !== undefined ? file.mtime : stats.mtime ;
			atime = file.atime !== undefined ? file.atime : stats.atime ;

			if ( stats.isDirectory() ) {
				children = await fs.promises.readdir( filePath ) ;
				children.forEach( child => {
					var childPath = path.join( filePath , child ) ;
					//log.hdebug( "adding child: %s" , childPath ) ;
					files.push( { filePath: childPath , prefix: path.join( prefix , fileName ) } ) ;
				} ) ;
				inputFile.close() ;
				this.directoryMap.set( key , { key , keySize , mode , mtime , atime } ) ;	/* eslint-disable-line object-curly-newline */
				directoryKeys.push( key ) ;
				continue ;
			}

			inputStream = fs.createReadStream( null , {
				fd: inputFile.fd ,
				autoClose: false
			} ) ;
		}
		else {
			key = path.join( options.prefix || '' , prefix , file.key ) ;
			if ( ! key ) { throw new Error( 'Missing key' ) ; }
			keySize = Buffer.byteLength( key ) ;
			if ( keySize > 255 ) { throw new Error( 'Key too large: ' + key ) ; }

			mode = file.mode !== undefined ? file.mode : 0o644 ;
			mtime = file.mtime !== undefined ? file.mtime : new Date() ;
			atime = file.atime !== undefined ? file.atime : new Date() ;

			if ( file.stream ) {
				inputStream = file.stream ;
			}
			else if ( file.buffer ) {
				inputStream = new streamKit.BufferToReadable( file.buffer ) ;
			}
			else if ( file.directory ) {
				this.directoryMap.set( key , { key , keySize , mode , mtime , atime } ) ;	/* eslint-disable-line object-curly-newline */
				directoryKeys.push( key ) ;
				continue ;
			}
			else {
				log.error( "Bad entry: it should have either a 'filePath', a 'stream' or a 'buffer' property" ) ;
				continue ;
			}
		}

		keys.push( key ) ;
		dataOffset = this.eof ;

		outputStream = fs.createWriteStream( null , {
			fd: this.file.fd ,
			autoClose: false ,
			start: this.eof
		} ) ;

		middleStreams = [] ;
		if ( gzip ) { middleStreams.push( zlib.createGzip() ) ; }
		if ( encryption ) { middleStreams.push( new cryptoHelper.CipherStream( this.encryptionKey ) ) ; }
		streamKit.pipe( inputStream , ... middleStreams , outputStream ) ;

		await Promise.onceEventOrError( outputStream , 'finish' ) ;

		this.eof = outputStream.pos ;
		//dataSize = outputStream.bytesWritten ;	// unsafe / don't use
		dataSize = this.eof - dataOffset ;
		dataBlockSize += dataSize ;
		log.hdebug( "Written file %s (gzip: %n ; encryption: %n ; size: %i ; %i - %i )" , filePath || key , gzip , encryption , dataSize , dataOffset , this.eof ) ;

		// Don't forget to close the file, since autoClose is turned off!
		if ( file.filePath ) { inputFile.close() ; }

		/*
		if ( this.eof - dataOffset !== dataSize ) {
			log.error( "Error! Size and offset mismatch!\nfile: %s\nstart: %i\nend: %i\nsize: %i\nexpected size: %i\n" , file , dataOffset , this.eof , dataSize , this.eof - dataOffset ) ;
		}
		*/

		this.indexMap.set( key , {
			key ,
			keySize ,
			gzip ,
			encryption ,
			mode ,
			mtime ,
			atime ,
			offset: dataOffset ,
			size: dataSize
		} ) ;
	}


	// Rewrite datablock size
	dataBlockHeaderBuffer.writeUInt32BE( dataBlockSize , 1 ) ;	// reserve space for the datablock size
	await this.file.write( dataBlockHeaderBuffer , 0 , DATABLOCK_FIXED_SIZE , dataBlockOffset ) ;


	// Write directories
	for ( key of directoryKeys ) {
		directory = this.directoryMap.get( key ) ;
		directorySize = DIRECTORY_FIXED_SIZE + directory.keySize ;
		flags = FLAG_TYPE_DIRECTORY ;
		directoryBuffer.writeUInt8( flags , 0 ) ;
		directoryBuffer.writeUInt16BE( directory.mode , 1 ) ;
		directoryBuffer.writeDoubleBE( + directory.mtime , 3 ) ;
		directoryBuffer.writeDoubleBE( + directory.atime , 11 ) ;
		directoryBuffer.writeUInt8( directory.keySize , 19 ) ;
		directoryBuffer.write( directory.key , 20 ) ;
		await this.file.write( directoryBuffer , 0 , directorySize , this.eof ) ;
		this.eof += directorySize ;
		log.hdebug( "Writing directory: %n" , directory ) ;
	}

	// Write indexes
	for ( key of keys ) {
		index = this.indexMap.get( key ) ;
		indexSize = INDEX_FIXED_SIZE + index.keySize ;
		flags = FLAG_TYPE_INDEX ;
		if ( index.gzip ) { flags |= FLAG_GZIP ; }
		if ( index.encryption ) { flags |= FLAG_ENCRYPTION ; }
		indexBuffer.writeUInt8( flags , 0 ) ;
		indexBuffer.writeUInt32BE( index.offset , 1 ) ;
		indexBuffer.writeUInt32BE( index.size , 5 ) ;
		indexBuffer.writeUInt16BE( index.mode , 9 ) ;
		indexBuffer.writeDoubleBE( + index.mtime , 11 ) ;
		indexBuffer.writeDoubleBE( + index.atime , 19 ) ;
		indexBuffer.writeUInt8( index.keySize , 27 ) ;
		indexBuffer.write( index.key , 28 ) ;
		await this.file.write( indexBuffer , 0 , indexSize , this.eof ) ;
		this.eof += indexSize ;
		log.hdebug( "Writing index: %n" , index ) ;
	}
} ;



JsPak.prototype.extract = async function( targetDirectory ) {
	if ( ! this.loaded ) { await this.load() ; }

	var index , directory , filePath , fileName , fileDir , dirPath , dirName , dirDir ,
		outputStream , inputStream ,
		checkedDir = new Set() ;

	// Ensure target directory path
	await fsKit.ensurePath( targetDirectory ) ;

	for ( index of this.indexMap.values() ) {
		filePath = path.join( targetDirectory , index.key ) ;
		fileDir = path.dirname( filePath ) ;

		if ( fileName === '.' || fileName === '..' || fileName === '~' ) {
			log.error( "Ignoring bad key '%s', it should not be '.', '..' or '~'" , index.key ) ;
			continue ;
		}
		
		if ( ! checkedDir.has( fileDir ) ) {
			// Check for malicious input
			if ( path.isAbsolute( fileDir ) || fileDir.includes( '../' ) || fileDir.includes( '~/' ) ) {
				log.error( "Ignoring bad key '%s', it should not be absolute or contain ../ or ~/" , index.key ) ;
				continue ;
			}

			// Ensure directory path
			await fsKit.ensurePath( fileDir ) ;

			checkedDir.add( fileDir ) ;
		}

		log.hdebug( "Writing %s -- index: %n" , filePath , index ) ;

		inputStream = this.getStreamFromIndex( index ) ;
		//outputFile = await fs.promises.open( filePath , 'w' , index.mode ) ;
		//outputStream = fs.createWriteStream( null , { fd: outputFile.fd } ) ;
		outputStream = fs.createWriteStream( filePath ) ;
		streamKit.pipe( inputStream , outputStream ) ;

		await Promise.onceEventOrError( outputStream , 'finish' ) ;
		await fs.promises.utimes( filePath , index.atime , index.mtime ) ;
		//outputFile.close() ;
	}

	for ( directory of this.directoryMap.values() ) {
		dirPath = path.join( targetDirectory , directory.key ) ;
		dirName = path.basename( dirPath ) ;
		dirDir = path.dirname( dirPath ) ;

		if ( dirName === '.' || dirName === '..' || dirName === '~' ) {
			log.error( "Ignoring bad key '%s', it should not be '.', '..' or '~'" , directory.key ) ;
			continue ;
		}
		
		if ( ! checkedDir.has( dirDir ) ) {
			// Check for malicious input
			if ( path.isAbsolute( dirDir ) || dirDir.includes( '../' ) || dirDir.includes( '~/' ) ) {
				log.error( "Ignoring bad key '%s', it should not be absolute or contain ../ or ~/" , directory.key ) ;
				continue ;
			}

			// Ensure directory path
			await fsKit.ensurePath( dirDir ) ;

			checkedDir.add( dirDir ) ;
		}

		log.hdebug( "Checking/creating %s -- directory: %n" , dirPath , directory ) ;

		try {
			await fs.promises.mkdir( dirPath , { mode: directory.mode } ) ;
		}
		catch ( error ) {
			if ( error.code === 'EEXIST' ) {
				// Exists is a normal case, if so, we just change the mode
				await fs.promises.chmod( dirPath , directory.mode ) ;
			}
			else {
				throw error ;
			}
		}
		
		await fs.promises.utimes( dirPath , directory.atime , directory.mtime ) ;
	}
} ;



JsPak.prototype.has = function( key ) {
	return this.indexMap.has( key ) ;
} ;



JsPak.prototype.keys = function() {
	return [ ... this.indexMap.keys() ] ;
} ;



JsPak.prototype.getMeta = function( key ) {
	if ( ! this.loaded ) { throw new Error( 'Not loaded' ) ; }
	return this.indexMap.get( key ) ;
} ;



JsPak.prototype.getStream = function( key ) {
	if ( ! this.loaded ) { throw new Error( 'Not loaded' ) ; }

	var index = this.indexMap.get( key ) ;
	if ( ! index ) { return ; }

	return this.getStreamFromIndex( index ) ;
} ;



// Internal
JsPak.prototype.getStreamFromIndex = function( index ) {
	var inputStream , middleStreams = [] ;

	inputStream = fs.createReadStream( null , {
		fd: this.file.fd ,
		autoClose: false ,
		start: index.offset ,
		end: index.offset + index.size - 1
	} ) ;

	if ( index.encryption ) { middleStreams.push( new cryptoHelper.DecipherStream( this.encryptionKey ) ) ; }
	if ( index.gzip ) { middleStreams.push( zlib.createGunzip() ) ; }

	return streamKit.pipe( inputStream , ... middleStreams ) ;
} ;



JsPak.prototype.getBuffer = async function( key ) {
	if ( ! this.loaded ) { throw new Error( 'Not loaded' ) ; }

	var index = this.indexMap.get( key ) ;
	if ( ! index ) { return ; }

	var buffer = Buffer.allocUnsafe( index.size ) ;
	await this.file.read( buffer , 0 , index.size , index.offset ) ;

	if ( index.encryption ) { buffer = await cryptoHelper.decryptBuffer( buffer , this.encryptionKey ) ; }
	if ( index.gzip ) { buffer = await gunzipBuffer( buffer ) ; }

	return buffer ;
} ;



/*
	General file structure:
		- start with 'JPK' marking .jpk files
		- headers
		- indexes
		- datablock
		- ... maybe indexes and datablock again, when files are appended to the archive
*/

// Symbol for deleted index entry
const DELETED = {} ;



const MASK_TYPE = 3 ;
const FLAG_TYPE_HEADER = 0 ;
const FLAG_TYPE_INDEX = 1 ;
const FLAG_TYPE_DATABLOCK = 2 ;
const FLAG_TYPE_DIRECTORY = 3 ;

/*
	Header entry structure:
	Flags (1B) - Key LPS (1B) - Value LPS (1B) - Key - Value

	Values are string, the lib will cast known header based on the header name.
*/

/*
	Index entry structure:
	Flags (1B) - Data Offset (4B) - Data Size (4B) - Mode Flags (2B) - Modify Time (aka mtime) (8B) - Access Time (aka atime) (8B)
	- Key LPS (1B) - Key
*/

const INDEX_FIXED_SIZE = 28 ;						// size without the key (which has a variable length)
const INDEX_MAX_SIZE = INDEX_FIXED_SIZE + 256 ;		// maximum size of an index
const FLAG_DELETED = 4 ;							// this file/data was deleted by another addition
const FLAG_GZIP = 8 ;								// zlib compression
const FLAG_ENCRYPTION = 16 ;						// encryption

/*
	Directory Index entry structure:
	Flags (1B) - Mode Flags (2B) - Modify Time (aka mtime) (8B) - Access Time (aka atime) (8B)
	- Key LPS (1B) - Key
*/

const DIRECTORY_FIXED_SIZE = 20 ;						// size without the key (which has a variable length)
const DIRECTORY_MAX_SIZE = DIRECTORY_FIXED_SIZE + 256 ;		// maximum size of an index
//const FLAG_DELETED = 4 ;	// Exist, but same flag than regular index

/*
	Datablock entry structure:
	Flags (1B) - Size (4B) - Full data block
*/

const DATABLOCK_FIXED_SIZE = 5 ;						// size without the data itself (which has a variable length)

