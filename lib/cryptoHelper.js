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



const Stream = require( 'stream' ) ;
const crypto = require( 'crypto' ) ;

const log = require( 'logfella' ).global.use( 'JsPak/crypto' ) ;



const helper = {} ;
module.exports = helper ;

/*
	Some tutorial references:
	https://medium.com/@anned20/encrypting-files-with-nodejs-a54a0736a50a
	https://medium.com/@brandonstilson/lets-encrypt-files-with-node-85037bea8c0e
*/



const CIPHER_ALGO = 'aes-256-ctr' ;
const HMAC_ALGO = 'sha256' ;

const HMAC_SIZE = {
	sha256: 32
} ;



helper.createCipherKey = ( userKey ) =>
	crypto.createHash( 'sha256' )
		.update( userKey )
		.digest() ;



// Should be turned into real async encryption
helper.encryptBuffer = async ( buffer , userKey ) => {
	// Create the real cipher key from the user key/password
	var cipherKey = helper.createCipherKey( userKey ) ;

	// Create an initialization vector
	var initVector = crypto.randomBytes( 16 ) ;

	// Create a new cipher using the algorithm, key, and initVector
	var cipher = crypto.createCipheriv( CIPHER_ALGO , cipherKey , initVector ) ;

	// Create the new (encrypted) buffer
	var outputBuffer = Buffer.concat( [ initVector , cipher.update( buffer ) , cipher.final() ] ) ;

	return outputBuffer ;
} ;



// Should be turned into real async decryption
helper.decryptBuffer = async ( buffer , userKey ) => {
	// Create the real cipher key from the user key/password
	var cipherKey = helper.createCipherKey( userKey ) ;

	// Get the initVector: the first 16 bytes
	var initVector = buffer.slice( 0 , 16 ) ;

	// Get the rest
	var payload = buffer.slice( 16 ) ;

	// Create a decipher
	var decipher = crypto.createDecipheriv( CIPHER_ALGO , cipherKey , initVector ) ;

	// Create the new (decrypted) buffer
	var outputBuffer = Buffer.concat( [ decipher.update( payload ) , decipher.final() ] ) ;

	return outputBuffer ;
} ;



function CipherStream( userKey ) {
	Stream.Transform.call( this ) ;

	// Create the real cipher key from the user key/password
	this.cipherKey = helper.createCipherKey( userKey ) ;

	// Create an initialization vector
	this.initVector = crypto.randomBytes( 16 ) ;

	// Create a new cipher using the algorithm, key, and initVector
	this.cipher = crypto.createCipheriv( CIPHER_ALGO , this.cipherKey , this.initVector ) ;

	this.push( this.initVector ) ;
}

CipherStream.prototype = Object.create( Stream.Transform.prototype ) ;
CipherStream.prototype.constructor = CipherStream ;

helper.CipherStream = CipherStream ;



CipherStream.prototype._transform = function( buffer , encoding , callback ) {
	// Encrypt the buffer
	buffer = this.cipher.update( buffer ) ;
	this.push( buffer ) ;
	callback() ;
} ;



CipherStream.prototype._flush = function( callback ) {
	// Add remaining data...
	var buffer = this.cipher.final() ;
	if ( buffer.length ) { this.push( buffer ) ; }
	callback() ;
} ;



function DecipherStream( userKey ) {
	Stream.Transform.call( this ) ;

	// Create the real cipher key from the user key/password
	this.cipherKey = helper.createCipherKey( userKey ) ;
	this.initVector = null ;
	this.decipher = null ;
}

DecipherStream.prototype = Object.create( Stream.Transform.prototype ) ;
DecipherStream.prototype.constructor = DecipherStream ;

helper.DecipherStream = DecipherStream ;



DecipherStream.prototype._transform = function( buffer , encoding , callback ) {
	var remaining ;

	if ( ! this.decipher ) {
		remaining = 16 - ( this.initVector ? this.initVector.length : 0 ) ;
		this.initVector = buffer.slice( 0 , remaining ) ;

		if ( this.initVector.length < 16 ) { callback() ; return ; }

		this.decipher = crypto.createDecipheriv( CIPHER_ALGO , this.cipherKey , this.initVector ) ;

		if ( buffer.length <= remaining ) { callback() ; return ; }

		buffer = buffer.slice( remaining , Infinity ) ;
	}

	// Encrypt the buffer
	this.push( this.decipher.update( buffer ) ) ;
	callback() ;
} ;



DecipherStream.prototype._flush = function( callback ) {
	if ( this.decipher ) {
		// Add remaining data...
		this.push( this.decipher.final() ) ;
	}

	callback() ;
} ;



// Should be turned into real async hmac
helper.createHmac = ( userKey ) => {
	// Create the real hmac key from the user key/password
	var hmacKey = helper.createCipherKey( userKey ) ;

	// Create a new hmac object
	return crypto.createHmac( HMAC_ALGO , hmacKey ) ;
} ;



// Append HMAC at the end of a buffer
helper.appendHmacBuffer = async ( buffer , userKey ) => {
	// Create the real hmac key from the user key/password
	var hmacKey = helper.createCipherKey( userKey ) ;

	// Create a new hmac object
	var hmac = crypto.createHmac( HMAC_ALGO , hmacKey ) ;

	// Create the hash buffer
	hmac.update( buffer ) ;

	// Create the new (encrypted) buffer
	var outputBuffer = Buffer.concat( [ buffer , hmac.digest() ] ) ;

	return outputBuffer ;
} ;



// Check and remove HMAC from a buffer
helper.deHmacBuffer = async ( buffer , verify , userKey ) => {
	var hmacSize = HMAC_SIZE[ HMAC_ALGO ] ;

	// Create the new (decrypted) buffer
	var outputBuffer = buffer.slice( 0 , buffer.length - hmacSize ) ;

	if ( verify ) {
		// Create the real cipher key from the user key/password
		var hmacKey = helper.createCipherKey( userKey ) ;

		// Create a new hmac object
		var hmac = crypto.createHmac( HMAC_ALGO , hmacKey ) ;

		// Create the hash buffer
		hmac.update( outputBuffer ) ;

		// Compare the existing HMAC with the computed one
		if ( hmac.digest().compare( buffer.slice( buffer.length - hmacSize ) ) ) {
			throw new Error( 'HMAC mismatch! The file has been tampered!' ) ;
		}
	}

	return outputBuffer ;
} ;



function AppendHmacStream( userKey ) {
	Stream.Transform.call( this ) ;

	// Create the real cipher key from the user key/password
	this.hmacKey = helper.createCipherKey( userKey ) ;

	// Create a new cipher using the algorithm, key, and initVector
	this.hmac = crypto.createHmac( HMAC_ALGO , this.hmacKey ) ;
}

AppendHmacStream.prototype = Object.create( Stream.Transform.prototype ) ;
AppendHmacStream.prototype.constructor = AppendHmacStream ;

helper.AppendHmacStream = AppendHmacStream ;



AppendHmacStream.prototype._transform = function( buffer , encoding , callback ) {
	this.hmac.update( buffer ) ;
	// Pass through
	this.push( buffer ) ;
	callback() ;
} ;



AppendHmacStream.prototype._flush = function( callback ) {
	// Add HMAC at the end...
	this.push( this.hmac.digest() ) ;
	callback() ;
} ;



function DeHmacStream( verify , userKey ) {
	Stream.Transform.call( this ) ;

	// Create the real cipher key from the user key/password
	this.hmacKey = verify ? helper.createCipherKey( userKey ) : null ;
	this.hmac = verify ? crypto.createHmac( HMAC_ALGO , this.hmacKey ) : null ;
	this.hmacSize = HMAC_SIZE[ HMAC_ALGO ] ;
	this.lastBuffer = null ;
}

DeHmacStream.prototype = Object.create( Stream.Transform.prototype ) ;
DeHmacStream.prototype.constructor = DeHmacStream ;

helper.DeHmacStream = DeHmacStream ;



const BUFFER_LIMIT = 2 ** 16 ;

DeHmacStream.prototype._transform = function( buffer , encoding , callback ) {
	// We never send the current buffer
	if ( buffer.length >= this.hmacSize ) {
		if ( this.lastBuffer ) {
			if ( this.hmac ) { this.hmac.update( this.lastBuffer ) ; }
			this.push( this.lastBuffer ) ;
		}

		this.lastBuffer = buffer ;
	}
	else if ( this.lastBuffer ) {
		this.lastBuffer = Buffer.concat( this.lastBuffer , buffer ) ;

		// Avoid edge case where buffer is always small, but there are plenty of call
		if ( this.lastBuffer >= BUFFER_LIMIT ) {
			let toSend = this.lastBuffer.slice( 0 , this.lastBuffer.length - this.hmacSize ) ;
			this.lastBuffer = this.lastBuffer.slice( this.lastBuffer.length - this.hmacSize ) ;
			if ( this.hmac ) { this.hmac.update( toSend ) ; }
			this.push( toSend ) ;
		}
	}
	else {
		this.lastBuffer = buffer ;
	}

	callback() ;
} ;



DeHmacStream.prototype._flush = function( callback ) {
	if ( ! this.lastBuffer || this.lastBuffer.length < this.hmacSize ) {
		callback( new Error( 'Bad stream: missing HMAC.' ) ) ;
		return ;
	}

	var toSend = this.lastBuffer.slice( 0 , this.lastBuffer.length - this.hmacSize ) ;

	if ( this.hmac ) {
		let hmacBuffer = this.lastBuffer.slice( this.lastBuffer.length - this.hmacSize ) ;
		this.hmac.update( toSend ) ;
		if ( this.hmac.digest().compare( hmacBuffer ) ) {
			callback( new Error( 'Bad stream: HMAC mismatch! The stream has been tampered!' ) ) ;
			return ;
		}
	}

	this.push( toSend ) ;
	callback() ;
} ;

