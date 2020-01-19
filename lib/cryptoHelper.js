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

const CIPHER_ALGO = 'aes-256-ctr' ;
const HMAC_ALGO = 'sha256' ;

const log = require( 'logfella' ).global.use( 'JsPak/crypto' ) ;



const helper = {} ;
module.exports = helper ;

/*
	Some tutorial references:
	https://medium.com/@anned20/encrypting-files-with-nodejs-a54a0736a50a
	https://medium.com/@brandonstilson/lets-encrypt-files-with-node-85037bea8c0e
*/



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
		// /!\ And what if it's not long enough?
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
helper.hmacBuffer = async ( buffer , userKey ) => {
	// Create the real hmac key from the user key/password
	var hmacKey = helper.createCipherKey( userKey ) ;

	// Create a new hmac object
	var hmac = crypto.createHmac( HMAC_ALGO , hmacKey ) ;

	// Create the hash buffer
	hmac.update( buffer ) ;
	var outputBuffer = hmac.digest() ;

	return outputBuffer ;
} ;

