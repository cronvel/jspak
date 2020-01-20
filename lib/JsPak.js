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
		- HMAC

	Support for metadata:
		- encryption of index keys (aes-256-ctr + per key random init vector)
		- global HMAC for all metadata

	Other features:
		- Being able to hijack require(), so requiring JS inside the archive is possible, and get priority over local files
		  starting at the directory where the archive lies (may be configurable).
		- Support multiple files with a number scheme, the later superseding existing files (e.g. like Q3 pak0.pak, pak1.pak, ...),
		  allowing distribution of extension pack/patch.

	Maybe:
		- Support Brotli compression? (15-20% less size than gzip for common web files: html, css, js, etc)
*/

/*
	TODO:
		- delete/replace
		- HMAC to authenticate the file
		- requiring JS inside a .jpk
		- multiple files with override
		- compression-level option
		- auto-compression mode: compress only files that can be (exclude media files)

	HMAC is complicated:
	* if we HMAC only per file, one can remove a file entirely, by removing its index entry
	* if we HMAC the whole package, it will slow down the whole thing
	* also per-file HMAC should be appended, not prepended, because of streaming, but it will also complicate things
	* we can eventually HMAC per file, and HMAC index/directory/header blocks alone, the later is done on .load(),
	  the former is done when trying to extract/stream a file
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

const package_ = require( '../package.json' ) ;
const semver = require( 'semver' ) ;
const MAJOR_VERSION = semver.major( package_.version ) ;
const MINOR_VERSION = semver.minor( package_.version ) ;



function JsPak( filePath , options = {} ) {
	this.filePath = filePath ;
	this.file = null ;
	this.isNew = null ;			// True if the archive was created, false if it existed
	this.coreHeadersAdded = null ;	// Write essential header, like version
	this.loaded = false ;		// True if the file header and index are loaded
	this.eof = null ;			// End Of File offset
	this.headers = {} ;
	this.indexMap = new Map() ;
	this.directoryMap = new Map() ;
	this.encryptionKey = options.encryptionKey || '' ;

	this.shouldVerifyMetaHmac = options.verify || null ;		// HMAC for all blocks except content data (each files have its own hmac)
	this.shouldVerifyFileHmac = options.verify || null ;		// HMAC for content data
	this.metaHmac = null ;
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
	if ( this.loaded ) { return ; }
	await this.parseMeta( true , this.shouldVerifyMetaHmac ) ;
	if ( this.shouldVerifyMetaHmac ) { await this.verifyMetaHmac() ; }
} ;



JsPak.prototype.computeMetaHmac = function() {
	return this.parseMeta( ! this.loaded , true ) ;
} ;



JsPak.prototype.verifyMetaHmac = async function() {
	if ( ! this.loaded || ! this.metaHmac ) { await this.computeMetaHmac() ; }
	if ( ! this.headers.metaHmac ) {
		throw new Error( 'No meta HMAC found in the package! The integrity of the package cannot be proven!' ) ;
	}
	if ( this.metaHmac.compare( this.headers.metaHmac ) ) {
		log.error( "Meta HMAC mismatch --\n  Real meta HMAC: %z\nHeader meta HMAC: %z" , this.metaHmac , this.headers.metaHmac ) ;
		throw new Error( 'Meta HMAC mismatch! The package has been tampered!' ) ;
	}
} ;



JsPak.prototype.addMetaHmac = async function() {
	if ( ! this.loaded || ! this.metaHmac ) { await this.computeMetaHmac() ; }
	if ( this.headers.metaHmac ) {
		throw new Error( 'The meta HMAC header is already existing!' ) ;
	}
	await this.addHeader( 'metaHmac' , this.metaHmac , true ) ;
} ;



// Internal function used by .load() and .computeMetaHmac()
JsPak.prototype.parseMeta = async function( loadMeta_ , computeMetaHmac_ ) {
	var headerBuffer , keyBuffer , valueBuffer , position , hmac ,
		flags , type , header , index , directory , keySize , dataBlockSize ;

	if ( ! this.file ) { await this.open() ; }

	headerBuffer = Buffer.allocUnsafe( Math.max( HEADER_FIXED_SIZE , INDEX_FIXED_SIZE , DIRECTORY_FIXED_SIZE , DATABLOCK_FIXED_SIZE ) ) ;
	keyBuffer = Buffer.allocUnsafe( KEY_BUFFER_MAX_SIZE ) ;
	valueBuffer = Buffer.allocUnsafe( VALUE_BUFFER_MAX_SIZE ) ;
	position = 3 ;

	if ( computeMetaHmac_ ) {
		hmac = cryptoHelper.createHmac( this.encryptionKey ) ;
	}

	while ( position < this.eof ) {
		//log.hdebug( "bloc position: %i" , position ) ;
		await this.file.read( headerBuffer , 0 , 1 , position ++ ) ;
		flags = headerBuffer.readUInt8( 0 ) ;
		//log.hdebug( "flags: %i" , flags ) ;
		type = flags & MASK_TYPE ;

		if ( type === FLAG_TYPE_HEADER ) {
			await this.file.read( headerBuffer , 1 , HEADER_FIXED_SIZE - 1 , position ) ;
			position += HEADER_FIXED_SIZE - 1 ;

			header = {} ;
			keySize = headerBuffer.readUInt8( 1 ) ;
			header.valueSize = headerBuffer.readUInt16BE( 2 ) ;

			await this.file.read( keyBuffer , 0 , keySize , position ) ;
			position += keySize ;

			await this.file.read( valueBuffer , 0 , header.valueSize , position ) ;
			position += header.valueSize ;

			header.key = keyBuffer.toString( 'utf8' , 0 , keySize ) ;
			header.value = valueBuffer.slice( 0 , header.valueSize ) ;

			if ( loadMeta_ ) {
				// Cast and add header to 'this'
				this.castHeader( header ) ;
				//log.hdebug( "Header: %Y" , header ) ;
			}

			if ( computeMetaHmac_ && ! OUT_OF_HMAC.has( header.key ) ) {
				// (e.g.: HMAC is obviously out of HMAC)
				hmac.update( headerBuffer.slice( 0 , HEADER_FIXED_SIZE ) ) ;
				hmac.update( keyBuffer.slice( 0 , keySize ) ) ;
				hmac.update( valueBuffer.slice( 0 , header.valueSize ) ) ;
			}
		}
		else if ( type === FLAG_TYPE_INDEX ) {
			//log.hdebug( "position: %i" , position ) ;
			await this.file.read( headerBuffer , 1 , INDEX_FIXED_SIZE - 1 , position ) ;
			position += INDEX_FIXED_SIZE - 1 ;
			keySize = headerBuffer.readUInt16BE( 27 ) ;
			await this.file.read( keyBuffer , 0 , keySize , position ) ;
			position += keySize ;

			if ( loadMeta_ ) {
				index = {} ;
				index.offset = headerBuffer.readUInt32BE( 1 ) ;
				index.size = headerBuffer.readUInt32BE( 5 ) ;
				index.mode = headerBuffer.readUInt16BE( 9 ) ;
				index.mtime = new Date( headerBuffer.readDoubleBE( 11 ) ) ;
				index.atime = new Date( headerBuffer.readDoubleBE( 19 ) ) ;
				//index.keySize = keySize ;
				index.gzip = !! ( flags & FLAG_GZIP ) ;
				index.encryption = !! ( flags & FLAG_ENCRYPTION ) ;
				index.hmac = !! ( flags & FLAG_HMAC ) ;

				if ( index.encryption ) {
					index.key = ( await cryptoHelper.decryptBuffer( keyBuffer.slice( 0 , keySize ) , this.encryptionKey ) ).toString() ;
					//log.hdebug( "Key Encryption! bf: %s , aft: %s" , keyBuffer.toString( 'utf8' , 0 , keySize ) , index.key ) ;
				}
				else {
					index.key = keyBuffer.toString( 'utf8' , 0 , keySize ) ;
				}

				this.indexMap.set( index.key , index ) ;
				//log.hdebug( "Index: %Y" , index ) ;
			}

			if ( computeMetaHmac_ ) {
				hmac.update( headerBuffer.slice( 0 , INDEX_FIXED_SIZE ) ) ;
				hmac.update( keyBuffer.slice( 0 , keySize ) ) ;
			}
		}
		else if ( type === FLAG_TYPE_DIRECTORY ) {
			//log.hdebug( "position: %i" , position ) ;
			await this.file.read( headerBuffer , 1 , DIRECTORY_FIXED_SIZE - 1 , position ) ;
			position += DIRECTORY_FIXED_SIZE - 1 ;
			keySize = headerBuffer.readUInt16BE( 19 ) ;
			await this.file.read( keyBuffer , 0 , keySize , position ) ;
			position += keySize ;

			if ( loadMeta_ ) {
				directory = {} ;
				directory.mode = headerBuffer.readUInt16BE( 1 ) ;
				directory.mtime = new Date( headerBuffer.readDoubleBE( 3 ) ) ;
				directory.atime = new Date( headerBuffer.readDoubleBE( 11 ) ) ;
				//directory.keySize = headerBuffer.readUInt16BE( 19 ) ;
				directory.encryption = !! ( flags & FLAG_ENCRYPTION ) ;

				if ( directory.encryption ) {
					directory.key = ( await cryptoHelper.decryptBuffer( keyBuffer.slice( 0 , keySize ) , this.encryptionKey ) ).toString() ;
					//log.hdebug( "DirKey  Encryption! bf: %s , aft: %s\n\n" , keyBuffer.toString( 'utf8' , 0 , keySize ) , directory.key ) ;
				}
				else {
					directory.key = keyBuffer.toString( 'utf8' , 0 , keySize ) ;
				}

				this.directoryMap.set( directory.key , directory ) ;
				//log.hdebug( "Directory: %Y" , directory ) ;
			}

			if ( computeMetaHmac_ ) {
				hmac.update( headerBuffer.slice( 0 , DIRECTORY_FIXED_SIZE ) ) ;
				hmac.update( keyBuffer.slice( 0 , keySize ) ) ;
			}
		}
		else if ( type === FLAG_TYPE_DATABLOCK ) {
			// This is a datablock: skip it!
			await this.file.read( headerBuffer , 1 , DATABLOCK_FIXED_SIZE - 1 , position ) ;
			position += DATABLOCK_FIXED_SIZE - 1 ;
			dataBlockSize = headerBuffer.readUInt32BE( 1 ) ;
			position += dataBlockSize ;
			//log.hdebug( "Skipping Data Block of size: %iB" , dataBlockSize ) ;

			if ( computeMetaHmac_ ) {
				hmac.update( headerBuffer.slice( 0 , DATABLOCK_FIXED_SIZE ) ) ;
			}
		}

		//log.hdebug( "loop -- pos: %i , eof: %i" , position , this.eof ) ;
	}

	if ( loadMeta_ ) {
		this.loaded = true ;
	}

	if ( computeMetaHmac_ ) {
		this.metaHmac = hmac.digest() ;
		//log.hdebug( "HMAC: %n" , this.metaHmac.toString( 'base64' ) ) ;
		return this.metaHmac ;
	}

	return ;
} ;



JsPak.prototype.addCoreHeaders = async function() {
	if ( ! this.isNew || this.coreHeadersAdded ) { return ; }
	if ( ! this.loaded ) { await this.load() ; }
	this.coreHeadersAdded = true ;
	await this.addHeader( 'majorVersion' , MAJOR_VERSION , true ) ;
	await this.addHeader( 'minorVersion' , MINOR_VERSION , true ) ;
} ;



JsPak.prototype.addHeader = async function( key , value , internal = false ) {
	if ( ! this.loaded ) { await this.load() ; }
	if ( ! internal && this.isNew && ! this.coreHeadersAdded ) { await this.addCoreHeaders() ; }

	var valueBuffer , keyBuffer , fixedBuffer , flags ;

	// Will throw on unknown header
	valueBuffer = this.headerValueToBuffer( key , value ) ;
	keyBuffer = Buffer.from( key ) ;
	fixedBuffer = Buffer.allocUnsafe( HEADER_FIXED_SIZE ) ;

	flags = FLAG_TYPE_HEADER ;
	fixedBuffer.writeUInt8( flags , 0 ) ;
	fixedBuffer.writeUInt8( keyBuffer.length , 1 ) ;
	fixedBuffer.writeUInt16BE( valueBuffer.length , 2 ) ;
	await this.file.write( fixedBuffer , 0 , HEADER_FIXED_SIZE , this.eof ) ;
	this.eof += HEADER_FIXED_SIZE ;
	await this.file.write( keyBuffer , 0 , keyBuffer.length , this.eof ) ;
	this.eof += keyBuffer.length ;
	await this.file.write( valueBuffer , 0 , valueBuffer.length , this.eof ) ;
	this.eof += valueBuffer.length ;

	this.headers[ key ] = value ;
	//log.hdebug( "Writing header: %s %n" , key , value ) ;
} ;



JsPak.prototype.add = async function( files , options = {} ) {
	if ( ! this.loaded ) { await this.load() ; }
	if ( this.isNew && ! this.coreHeadersAdded ) { await this.addCoreHeaders() ; }

	if ( ! Array.isArray( files ) ) { files = [ files ] ; }

	// Check options.prefix, it should not be absolute, and should not contains ../ ~/
	if ( options.prefix ) {
		if ( path.isAbsolute( options.prefix ) || options.prefix.includes( '../' ) || options.prefix.includes( '~/' ) ) {
			throw new Error( "Bad prefix '" + options.prefix + "', it should not be absolute or contains ../ or ~/" ) ;
		}
	}

	var key , keys = [] , directoryKeys = [] , keySize , flags , gzip , encryption , hmac , mode , mtime , atime ,
		file , filePath , fileName , prefix , stats , children ,
		dataBlockOffset , dataBlockSize ,
		directory , index , dataOffset = 0 , dataSize = 0 ,
		directoryBuffer , indexBuffer , dataBlockHeaderBuffer , keyBuffer , currentKeyBuffer ,
		inputFile , inputStream , outputStream , middleStreams ;

	dataBlockHeaderBuffer = Buffer.allocUnsafe( DATABLOCK_FIXED_SIZE ) ;
	directoryBuffer = indexBuffer = Buffer.allocUnsafe( Math.max( INDEX_FIXED_SIZE , DIRECTORY_FIXED_SIZE ) ) ;
	//directoryBuffer = indexBuffer = Buffer.allocUnsafe( Math.max( INDEX_MAX_SIZE , DIRECTORY_MAX_SIZE ) ) ;
	keyBuffer = Buffer.allocUnsafe( KEY_BUFFER_MAX_SIZE ) ;


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
		hmac = file.hmac !== undefined ? file.hmac : !! options.hmac ;

		if ( file.filePath ) {
			// This is a file
			filePath = file.filePath ;
			fileName = path.basename( filePath ) ;
			key = path.join( options.prefix || '' , prefix , fileName ) ;
			keySize = Buffer.byteLength( key ) ;
			if ( keySize >= KEY_MAX_SIZE ) { throw new Error( 'Key too large: ' + key ) ; }

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
				this.directoryMap.set( key , { key , keySize , mode , mtime , atime , encryption } ) ;	/* eslint-disable-line object-curly-newline */
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
			if ( keySize >= KEY_MAX_SIZE ) { throw new Error( 'Key too large: ' + key ) ; }

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
		if ( hmac ) { middleStreams.push( new cryptoHelper.AppendHmacStream( this.encryptionKey ) ) ; }
		streamKit.pipe( inputStream , ... middleStreams , outputStream ) ;

		await Promise.onceEventOrError( outputStream , 'finish' ) ;

		this.eof = outputStream.pos ;
		//dataSize = outputStream.bytesWritten ;	// unsafe / don't use
		dataSize = this.eof - dataOffset ;
		dataBlockSize += dataSize ;
		log.hdebug( "Written file %s (gzip: %n ; encryption: %n ; hmac: %n ; size: %i ; %i - %i )" , filePath || key , gzip , encryption , hmac , dataSize , dataOffset , this.eof ) ;

		// Don't forget to close the file, since autoClose is turned off!
		if ( file.filePath ) { inputFile.close() ; }

		this.indexMap.set( key , { key , keySize , gzip , encryption , hmac , mode , mtime , atime , offset: dataOffset , size: dataSize } ) ; /* eslint-disable-line object-curly-newline */
	}


	// Rewrite datablock size
	dataBlockHeaderBuffer.writeUInt32BE( dataBlockSize , 1 ) ;	// reserve space for the datablock size
	await this.file.write( dataBlockHeaderBuffer , 0 , DATABLOCK_FIXED_SIZE , dataBlockOffset ) ;


	// Write directories
	for ( key of directoryKeys ) {
		directory = this.directoryMap.get( key ) ;
		keyBuffer.write( directory.key ) ;
		currentKeyBuffer = keyBuffer ;
		//directorySize = DIRECTORY_FIXED_SIZE + directory.keySize ;
		flags = FLAG_TYPE_DIRECTORY ;
		if ( directory.encryption ) {
			flags |= FLAG_ENCRYPTION ;
			currentKeyBuffer = await cryptoHelper.encryptBuffer( keyBuffer.slice( 0 , directory.keySize ) , this.encryptionKey ) ;
			directory.key = currentKeyBuffer.toString() ;
			directory.keySize = currentKeyBuffer.length ;
		}
		directoryBuffer.writeUInt8( flags , 0 ) ;
		directoryBuffer.writeUInt16BE( directory.mode , 1 ) ;
		directoryBuffer.writeDoubleBE( + directory.mtime , 3 ) ;
		directoryBuffer.writeDoubleBE( + directory.atime , 11 ) ;
		directoryBuffer.writeUInt16BE( directory.keySize , 19 ) ;
		//directoryBuffer.write( directory.key , 21 ) ;
		//await this.file.write( directoryBuffer , 0 , directorySize , this.eof ) ;
		await this.file.write( directoryBuffer , 0 , DIRECTORY_FIXED_SIZE , this.eof ) ;
		this.eof += DIRECTORY_FIXED_SIZE ;
		await this.file.write( currentKeyBuffer , 0 , directory.keySize , this.eof ) ;
		this.eof += directory.keySize ;
		//this.eof += directorySize ;
		//log.hdebug( "Writing directory: %n" , directory ) ;
	}

	// Write indexes
	for ( key of keys ) {
		index = this.indexMap.get( key ) ;
		keyBuffer.write( index.key ) ;
		currentKeyBuffer = keyBuffer ;
		//indexSize = INDEX_FIXED_SIZE + index.keySize ;
		flags = FLAG_TYPE_INDEX ;
		if ( index.gzip ) { flags |= FLAG_GZIP ; }
		if ( index.encryption ) {
			flags |= FLAG_ENCRYPTION ;
			currentKeyBuffer = await cryptoHelper.encryptBuffer( keyBuffer.slice( 0 , index.keySize ) , this.encryptionKey ) ;
			index.key = currentKeyBuffer.toString() ;
			index.keySize = currentKeyBuffer.length ;
		}
		if ( index.hmac ) { flags |= FLAG_HMAC ; }
		indexBuffer.writeUInt8( flags , 0 ) ;
		indexBuffer.writeUInt32BE( index.offset , 1 ) ;
		indexBuffer.writeUInt32BE( index.size , 5 ) ;
		indexBuffer.writeUInt16BE( index.mode , 9 ) ;
		indexBuffer.writeDoubleBE( + index.mtime , 11 ) ;
		indexBuffer.writeDoubleBE( + index.atime , 19 ) ;
		indexBuffer.writeUInt16BE( index.keySize , 27 ) ;
		//indexBuffer.write( index.key , 29 ) ;
		//await this.file.write( indexBuffer , 0 , indexSize , this.eof ) ;
		await this.file.write( indexBuffer , 0 , INDEX_FIXED_SIZE , this.eof ) ;
		this.eof += INDEX_FIXED_SIZE ;
		await this.file.write( currentKeyBuffer , 0 , index.keySize , this.eof ) ;
		this.eof += index.keySize ;
		//this.eof += indexSize ;
		//log.hdebug( "Writing index: %n" , index ) ;
	}
} ;



JsPak.prototype.extract = async function( targetDirectory ) {
	if ( ! this.loaded ) { await this.load() ; }

	var index , directory , filePath , fileName , fileDir , dirPath , dirName , dirDir ,
		outputStream , inputStream , sortedDirectories ,
		checkedDir = new Set() ;

	// Ensure target directory path
	await fsKit.ensurePath( targetDirectory ) ;

	// Creating files
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

		//log.hdebug( "Writing %s -- index: %n" , filePath , index ) ;

		inputStream = this.getStreamFromIndex( index ) ;
		//outputFile = await fs.promises.open( filePath , 'w' , index.mode ) ;
		//outputStream = fs.createWriteStream( null , { fd: outputFile.fd } ) ;
		outputStream = fs.createWriteStream( filePath , { mode: index.mode } ) ;
		streamKit.pipe( inputStream , outputStream ) ;

		await Promise.onceEventOrError( outputStream , 'finish' ) ;
		await fs.promises.utimes( filePath , index.atime , index.mtime ) ;
		//outputFile.close() ;
	}

	// Cheap trick: sort longer keys first, because we need to set modes from the descendant first,
	// doing it ancestors first causes errors: ancestors may forbid access (e.g. set mode with no x)
	// to its descendant
	sortedDirectories = [ ... this.directoryMap.values() ].sort( ( a , b ) => b.key.length - a.key.length ) ;

	for ( directory of sortedDirectories ) {
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

		//log.hdebug( "Creating/chmoding %s -- directory: %n" , dirPath , directory ) ;

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



JsPak.prototype.directoryKeys = function() {
	return [ ... this.directoryMap.keys() ] ;
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

	if ( index.hmac ) {
		if ( this.shouldVerifyFileHmac && ! index.hmacMatch ) {
			if ( index.hmacMatch === false ) {
				throw new Error( 'HMAC already failed for this file!' ) ;
			}

			let stream = new cryptoHelper.DeHmacStream( true , this.encryptionKey ) ;
			middleStreams.push( stream ) ;
			stream.on( 'end' , () => index.hmacMatch = stream.hmacMatch ) ;
		}
		else {
			middleStreams.push( new cryptoHelper.DeHmacStream( false , this.encryptionKey ) ) ;
		}
	}
	if ( index.encryption ) { middleStreams.push( new cryptoHelper.DecipherStream( this.encryptionKey ) ) ; }
	if ( index.gzip ) { middleStreams.push( zlib.createGunzip() ) ; }

	return streamKit.pipe( inputStream , ... middleStreams ) ;
} ;



JsPak.prototype.getBuffer = async function( key ) {
	if ( ! this.loaded ) { throw new Error( 'Not loaded' ) ; }

	var index = this.indexMap.get( key ) ;
	if ( ! index ) { return ; }

	var verify = ! index.verified && this.shouldVerifyFileHmac ;

	var buffer = Buffer.allocUnsafe( index.size ) ;
	await this.file.read( buffer , 0 , index.size , index.offset ) ;

	if ( index.hmac ) {
		buffer = await cryptoHelper.deHmacBuffer( buffer , verify , this.encryptionKey ) ;
		if ( verify ) { index.verified = true ; }
	}

	if ( index.hmac ) {
		if ( this.shouldVerifyFileHmac && ! index.hmacMatch ) {
			if ( index.hmacMatch === false ) {
				throw new Error( 'HMAC already failed for this file!' ) ;
			}

			buffer = await cryptoHelper.deHmacBuffer( buffer , true , this.encryptionKey ) ;
			index.hmacMatch = true ;
		}
		else {
			buffer = await cryptoHelper.deHmacBuffer( buffer , false , this.encryptionKey ) ;
		}
	}
	if ( index.encryption ) { buffer = await cryptoHelper.decryptBuffer( buffer , this.encryptionKey ) ; }
	if ( index.gzip ) { buffer = await gunzipBuffer( buffer ) ; }

	return buffer ;
} ;



const KNOWN_HEADERS = {
	majorVersion: 'uint8' ,
	minorVersion: 'uint8' ,
	metaHmac: 'buffer'
} ;

// Header that can't be in HMAC
const OUT_OF_HMAC = new Set( [ 'metaHmac' ] ) ;



JsPak.prototype.castHeader = function( header ) {
	if ( ! header.key ) { return ; }

	var type = KNOWN_HEADERS[ header.key ] || 'buffer' ;

	switch ( type ) {
		case 'uint8' :
			if ( header.valueSize !== 1 ) { return ; }
			header.value = header.value.readUInt8() ;
			break ;
		case 'uint16' :
			if ( header.valueSize !== 2 ) { return ; }
			header.value = header.value.readUInt16BE() ;
			break ;
		case 'uint32' :
			if ( header.valueSize !== 4 ) { return ; }
			header.value = header.value.readUInt32BE() ;
			break ;
		case 'string' :
			header.value = header.value.toString() ;
			break ;
		case 'buffer' :
			// Copy the value to a new Buffer
			header.value = Buffer.from( header.value ) ;
			break ;
	}

	this.headers[ header.key ] = header.value ;
} ;



JsPak.prototype.headerValueToBuffer = function( key , value ) {
	var buffer ,
		type = KNOWN_HEADERS[ key ] ;

	if ( ! type ) { throw new Error( "Unknown header '" + key + "'." ) ; }

	switch ( type ) {
		case 'uint8' :
			value = Math.floor( + value || 0 ) ;
			buffer = Buffer.allocUnsafe( 1 ) ;
			buffer.writeUInt8( value ) ;
			break ;
		case 'uint16' :
			value = Math.floor( + value || 0 ) ;
			buffer = Buffer.allocUnsafe( 2 ) ;
			buffer.writeUInt16BE( value ) ;
			break ;
		case 'uint32' :
			value = Math.floor( + value || 0 ) ;
			buffer = Buffer.allocUnsafe( 4 ) ;
			buffer.writeUInt32BE( value ) ;
			break ;
		case 'string' :
			value = '' + value ;
			if ( Buffer.byteLength( value ) > VALUE_BUFFER_MAX_SIZE ) { throw new Error( "Header '" + key + "' too big." ) ; }
			buffer = Buffer.from( value ) ;
			break ;
		case 'buffer' :
			if ( ! Buffer.isBuffer( value ) ) { throw new TypeError( "Header '" + key + "' should be a Buffer." ) ; }
			if ( value.length > VALUE_BUFFER_MAX_SIZE ) { throw new Error( "Header '" + key + "' too big." ) ; }
			buffer = Buffer.from( value ) ;
			break ;
	}

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

const VALUE_BUFFER_MAX_SIZE = 2 ** 16 ;				// maximum size of key

/*
	Header entry structure:
	Flags (1B) - Key LPS (1B) - Value LPS (2B) - Key - Value

	Values are buffer, the lib will cast known header based on the header name.
*/

const HEADER_FIXED_SIZE = 4 ;			// size without the key and value (both have a variable length)

/*
	Index entry structure:
	Flags (1B) - Data Offset (4B) - Data Size (4B) - Mode Flags (2B) - Modify Time (aka mtime) (8B) - Access Time (aka atime) (8B)
	- Key LPS (2B) - Key
*/

const INDEX_FIXED_SIZE = 29 ;						// size without the key (which has a variable length)
const KEY_BUFFER_MAX_SIZE = 2 ** 16 ;				// maximum size of key
const KEY_MAX_SIZE = KEY_BUFFER_MAX_SIZE - 1024 ;	// because of crypto, we remove 16B for the init vector, and a large space for eventual HMAC and its evolution
const INDEX_MAX_SIZE = INDEX_FIXED_SIZE + KEY_MAX_SIZE ;	// maximum size of an index
const FLAG_DELETED = 4 ;							// this file/data was deleted by another addition
const FLAG_GZIP = 8 ;								// zlib compression
// bit16 is reserved: can be grouped with bit8 to have multiple compression type (e.g.: brotli, or the next big player)
const FLAG_ENCRYPTION = 32 ;						// encryption
// bit64 reserved for asymetric encryption?
const FLAG_HMAC = 128 ;								// the file has an HMAC

/*
	Directory Index entry structure:
	Flags (1B) - Mode Flags (2B) - Modify Time (aka mtime) (8B) - Access Time (aka atime) (8B)
	- Key LPS (2B) - Key
*/

const DIRECTORY_FIXED_SIZE = 21 ;						// size without the key (which has a variable length)
const DIRECTORY_MAX_SIZE = DIRECTORY_FIXED_SIZE + KEY_MAX_SIZE ;		// maximum size of an index
// bit4 is FLAG_DELETED from index flags
// bit32 is FLAG_ENCRYPTION from index flags

/*
	Datablock entry structure:
	Flags (1B) - Size (4B) - Full data block
*/

const DATABLOCK_FIXED_SIZE = 5 ;						// size without the data itself (which has a variable length)

