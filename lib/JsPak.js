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
	this.map = new Map() ;
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
	var buffer , position , flags , type , index , dataBlockSize ;

	if ( this.loaded ) { return ; }
	if ( ! this.file ) { await this.open() ; }

	if ( this.eof <= 3 ) {
		this.loaded = true ;
		return ;
	}

	buffer = Buffer.allocUnsafe( INDEX_MAX_SIZE ) ;
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
			index.btime = buffer.readDoubleBE( 11 ) ;
			index.ctime = buffer.readDoubleBE( 19 ) ;
			index.keySize = buffer.readUInt8( 27 ) ;
			index.gzip = flags & FLAG_GZIP ;
			index.encryption = flags & FLAG_ENCRYPTION ;

			await this.file.read( buffer , INDEX_FIXED_SIZE , index.keySize , position ) ;
			position += index.keySize ;
			index.key = buffer.toString( 'utf8' , 28 , 28 + index.keySize ) ;

			this.map.set( index.key , index ) ;
			log.hdebug( "Index: %Y" , index ) ;
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

	var key , keys = [] , keySize , flags , gzip , encryption , mode , btime , ctime ,
		file , filePath , fileName , prefix , stats , children ,
		dataBlockOffset , dataBlockSize ,
		index , indexSize , dataOffset = 0 , dataSize = 0 ,
		indexBuffer , dataBlockHeaderBuffer ,
		inputFile , inputStream , outputStream , middleStreams ;

	dataBlockHeaderBuffer = Buffer.allocUnsafe( DATABLOCK_FIXED_SIZE ) ;
	indexBuffer = Buffer.allocUnsafe( INDEX_MAX_SIZE ) ;


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
		
		prefix = file.prefix || '' ;
		gzip = file.gzip !== undefined ? file.gzip : !! options.gzip ;
		encryption = file.encryption !== undefined ? file.encryption : !! options.encryption ;

		if ( file.filePath ) {
			// This is a file
			fileName = path.basename( file ) ;
			key = path.join( options.prefix || '' , prefix , fileName ) ;
			keySize = Buffer.byteLength( key ) ;
			if ( keySize > 255 ) { throw new Error( 'Key too large: ' + key ) ; }

			inputFile = await fs.promises.open( file , 'r' ) ;
			stats = await inputFile.stat() ;

			if ( stats.isDirectory() ) {
				children = await fs.promises.readdir( file ) ;
				children.forEach( child => {
					var childPath = path.join( file , child ) ;
					//log.hdebug( "adding child: %s" , childPath ) ;
					files.push( { filePath: childPath , prefix: path.join( prefix , fileName ) } ) ;
				} ) ;
				inputFile.close() ;
				continue ;
			}

			mode = file.mode !== undefined ? file.mode : stats.mode ;
			btime = file.btime !== undefined ? file.btime : stats.birthtimeMs ;
			ctime = file.ctime !== undefined ? file.ctime : stats.ctimeMs ;

			inputStream = fs.createReadStream( null , {
				fd: inputFile.fd ,
				autoClose: false
			} ) ;
		}
		else {
			key = file.key ;
			if ( ! key ) { throw new Error( 'Missing key' ) ; }
			keySize = Buffer.byteLength( key ) ;
			if ( keySize > 255 ) { throw new Error( 'Key too large: ' + key ) ; }

			mode = file.mode !== undefined ? file.mode : 0o644 ;
			btime = file.btime !== undefined ? file.btime : Date.now() ;
			ctime = file.ctime !== undefined ? file.ctime : Date.now() ;
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
		log.hdebug( "Writing file %s (fd: %i ; gzip: %n ; encryption: %n ; size: %i ; %i - %i )" , file , inputFile.fd , gzip , encryption , dataSize , dataOffset , this.eof ) ;

		/*
		if ( this.eof - dataOffset !== dataSize ) {
			log.error( "Error! Size and offset mismatch!\nfile: %s\nstart: %i\nend: %i\nsize: %i\nexpected size: %i\n" , file , dataOffset , this.eof , dataSize , this.eof - dataOffset ) ;
		}
		*/

		this.map.set( key , {
			key ,
			keySize ,
			gzip ,
			encryption ,
			mode ,
			btime ,
			ctime ,
			offset: dataOffset ,
			size: dataSize
		} ) ;

		// Don't forget to close the file, since autoClose is turned off!
		inputFile.close() ;
	}


	// Rewrite datablock size
	dataBlockHeaderBuffer.writeUInt32BE( dataBlockSize , 1 ) ;	// reserve space for the datablock size
	await this.file.write( dataBlockHeaderBuffer , 0 , DATABLOCK_FIXED_SIZE , dataBlockOffset ) ;


	// Write indexes
	for ( key of keys ) {
		index = this.map.get( key ) ;
		indexSize = INDEX_FIXED_SIZE + index.keySize ;
		flags = FLAG_TYPE_INDEX ;
		if ( index.gzip ) { flags |= FLAG_GZIP ; }
		if ( index.encryption ) { flags |= FLAG_ENCRYPTION ; }
		indexBuffer.writeUInt8( flags , 0 ) ;
		indexBuffer.writeUInt32BE( index.offset , 1 ) ;
		indexBuffer.writeUInt32BE( index.size , 5 ) ;
		indexBuffer.writeUInt16BE( index.mode , 9 ) ;
		indexBuffer.writeDoubleBE( index.btime , 11 ) ;
		indexBuffer.writeDoubleBE( index.ctime , 19 ) ;
		indexBuffer.writeUInt8( index.keySize , 27 ) ;
		indexBuffer.write( index.key , 28 ) ;
		await this.file.write( indexBuffer , 0 , indexSize , this.eof ) ;
		this.eof += indexSize ;
		log.hdebug( "Writing index: %n" , index ) ;
	}
} ;



JsPak.prototype.extract = async function( directory ) {
	if ( ! this.loaded ) { await this.load() ; }

	var index , filePath , fileDir , outputStream , inputStream ,
		checkedDir = new Set() ;

	// Ensure target directory path
	await fsKit.ensurePath( directory ) ;

	for ( [ , index ] of this.map ) {
		filePath = path.join( directory , index.key ) ;
		fileDir = path.dirname( filePath ) ;

		if ( ! checkedDir.has( fileDir ) ) {
			// Check for malicious input
			if ( path.isAbsolute( fileDir ) || fileDir.includes( '../' ) || fileDir.includes( '~/' ) ) {
				log.error( "Ignoring bad key '%s', it should not be absolute or contains ../ or ~/" , fileDir ) ;
				continue ;
			}

			// Ensure directory path
			await fsKit.ensurePath( fileDir ) ;

			checkedDir.add( fileDir ) ;
		}

		log.hdebug( "Writing %s -- index: %n" , filePath , index ) ;

		inputStream = this.getStreamFromIndex( index ) ;
		outputStream = fs.createWriteStream( filePath ) ;
		streamKit.pipe( inputStream , outputStream ) ;

		await Promise.onceEventOrError( outputStream , 'finish' ) ;
	}
} ;



JsPak.prototype.has = function( key ) {
	return this.map.has( key ) ;
} ;



JsPak.prototype.keys = function() {
	return [ ... this.map.keys() ] ;
} ;



JsPak.prototype.getMeta = function( key ) {
	if ( ! this.loaded ) { throw new Error( 'Not loaded' ) ; }
	return this.map.get( key ) ;
} ;



JsPak.prototype.getStream = function( key ) {
	if ( ! this.loaded ) { throw new Error( 'Not loaded' ) ; }

	var index = this.map.get( key ) ;
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

	var index = this.map.get( key ) ;
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

/*
	Header entry structure:
	Flags (1B) - Key LPS (1B) - Value LPS (1B) - Key - Value

	Values are string, the lib will cast known header based on the header name.
*/

/*
	Index entry structure:
	Flags (1B) - Data Offset (4B) - Data Size (4B) - Mode Flags (2B) - Birth Time (8B) - Change Time (aka ctime) (8B)
	- Key LPS (1B) - Key
*/

const INDEX_FIXED_SIZE = 28 ;						// size without the key (which has a variable length)
const INDEX_MAX_SIZE = INDEX_FIXED_SIZE + 256 ;		// maximum size of an index
const FLAG_DELETED = 4 ;							// this file/data was deleted by another addition
const FLAG_GZIP = 8 ;								// zlib compression
const FLAG_ENCRYPTION = 16 ;						// encryption

/*
	Datablock entry structure:
	Flags (1B) - Size (4B) - Full data block
*/

const DATABLOCK_FIXED_SIZE = 5 ;						// size without the data itself (which has a variable length)

