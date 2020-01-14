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



const fsPromise = require( 'fs' ).promises ;
const Promise = require( 'seventh' ) ;

const log = require( 'logfella' ).global.use( 'JsPak' ) ;



function JsPak( filePath , options = {} ) {
	this.filePath = filePath ;
	this.file = null ;
	this.loaded = false ;		// True if the file header and index are loaded
	this.eof = null ;			// End Of File offset
	this.map = new Map() ;
}

module.exports = JsPak ;



// Open the file
JsPak.prototype.open = async function() {
	if ( this.file ) { return ; }

	try {
		this.file = await fsPromise.open( this.filePath , 'r+' ) ;
		let stats = await this.file.stat() ;
		this.eof = stats.size ;
	}
	catch ( error ) {
		if ( error.code === 'ENOENT' ) {
			this.file = await fsPromise.open( this.filePath , 'w+' ) ;
			this.file.write( 'JPK' ) ;
			this.loaded = true ;
			this.eof = 3 ;
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



JsPak.prototype.add = async function( filePaths ) {
	if ( ! this.loaded ) { await this.load() ; }

	var key , keys = [] , keySize , flags ,
		filePath , inputFile , inputPosition , chunkSize , result ,
		stats , buffer , index , indexSize , indexesSize = 0 , dataOffset = 0 , dataSize = 0 ;

	if ( Array.isArray( filePaths ) ) { filePaths = new Set( filePaths ) ; }
	else if ( ! ( filePaths instanceof Set ) ) { throw new Error( 'The filePaths argument should be an Array or a Set.' ) ; }

	buffer = Buffer.allocUnsafe( INDEX_MAX_SIZE ) ;

	// Collect data
	for ( filePath of filePaths ) {
		stats = await fsPromise.lstat( filePath ) ;

		// Remove initial '/', and tranform filePath

		key = filePath ;
		keys.push( key ) ;
		keySize = Buffer.byteLength( key ) ;
		if ( keySize > 255 ) { throw new Error( 'Key too long: ' + key ) ; }
		this.map.set( key , {
			key ,
			keySize ,
			inputFilePath: filePath ,
			offset: null ,	// can't predict that now
			size: stats.size ,
			mode: stats.mode ,
			btime: stats.birthtimeMs ,
			ctime: stats.ctimeMs
		} ) ;
		indexesSize += INDEX_FIXED_SIZE + keySize ;
		dataSize += stats.size ;
	}

	// Write indexes
	dataOffset = this.eof + indexesSize + DATABLOCK_FIXED_SIZE ;
	for ( key of keys ) {
		index = this.map.get( key ) ;
		indexSize = INDEX_FIXED_SIZE + index.keySize ;
		index.offset = dataOffset ;
		flags = FLAG_TYPE_INDEX ;
		buffer.writeUInt8( flags , 0 ) ;
		buffer.writeUInt32BE( index.offset , 1 ) ;
		buffer.writeUInt32BE( index.size , 5 ) ;
		buffer.writeUInt16BE( index.mode , 9 ) ;
		buffer.writeDoubleBE( index.btime , 11 ) ;
		buffer.writeDoubleBE( index.ctime , 19 ) ;
		buffer.writeUInt8( index.keySize , 27 ) ;
		buffer.write( index.key , 28 ) ;
		await this.file.write( buffer , 0 , indexSize , this.eof ) ;
		this.eof += indexSize ;
		dataOffset += index.size ;
		log.hdebug( "Writing index: %n" , index ) ;
	}


	// Write data block

	// First write the data block flags and size
	flags = FLAG_TYPE_DATABLOCK ;
	buffer.writeUInt8( flags , 0 ) ;
	buffer.writeUInt32BE( dataSize , 1 ) ;
	await this.file.write( buffer , 0 , DATABLOCK_FIXED_SIZE , this.eof ) ;
	this.eof += DATABLOCK_FIXED_SIZE ;

	buffer = Buffer.allocUnsafe( COPY_BUFFER_SIZE ) ;

	// Now write each file
	for ( key of keys ) {
		index = this.map.get( key ) ;
		inputFile = await fsPromise.open( index.inputFilePath ) ;

		inputPosition = 0 ;

		try {
			while ( inputPosition < index.size ) {
				chunkSize = Math.min( COPY_BUFFER_SIZE , index.size - inputPosition ) ;
				result = await inputFile.read( buffer , 0 , chunkSize , inputPosition ) ;
				if ( ! result.bytesRead ) { throw new Error( 'File too short' ) ; }
				await this.file.write( buffer , 0 , result.bytesRead , this.eof ) ;
				log.hdebug( "Written chunk: %kB of file %s" , result.bytesRead , index.inputFilePath ) ;
				inputPosition += result.bytesRead ;
				this.eof += result.bytesRead ;
			}
		}
		catch ( error ) {
			log.error( "%E" , error ) ;
		}
	}
} ;



/*
	Support for global archive:
		- global encryption (should be fast):
			- for index, encrypt after KeyLPS (offset, size, key, ...)
			- for datablock, encrypt the full data block (after size)
		  ... so navigating entry is still possible

	Support per file/data:
		- zlib compression
		- encryption of a single file

	Other features:
		- Being able to hijack require(), so requiring JS inside the archive is possible, and get priority over local files
		  starting at the directory where the archive lies (may be configurable).
		- Support multiple files with a number scheme, the later superseding existing files (e.g. like Q3 pak0.pak, pak1.pak, ...),
		  allowing distribution of extension pack/patch.
*/

/*
	General file structure:
		- start with 'JPK' marking .jpk files
		- headers
		- indexes
		- datablock
		- ... maybe indexes and datablock again, when files are appended to the archive
*/

// Symbole for deleted index entry
const DELETED = {} ;
const COPY_BUFFER_SIZE = 2 ** 16 ;



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
const FLAG_Z = 8 ;									// zlib compression
const FLAG_ENCRYPTION = 16 ;						// encryption

/*
	Datablock entry structure:
	Flags (1B) - Size (4B) - Full data block
*/

const DATABLOCK_FIXED_SIZE = 5 ;						// size without the data itself (which has a variable length)

