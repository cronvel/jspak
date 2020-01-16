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
const algorithm = 'aes-256-ctr' ;

const log = require( 'logfella' ).global.use( 'JsPak/crypto' ) ;



const helper = {} ;
module.exports = helper ;

/*
	References:
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
	var cipher = crypto.createCipheriv( algorithm , cipherKey , initVector ) ;

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
	var decipher = crypto.createDecipheriv( algorithm , cipherKey , initVector ) ;

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
	this.injectedHeader = false ;

	// Create a new cipher using the algorithm, key, and initVector
	this.cipher = crypto.createCipheriv( algorithm , this.cipherKey , this.initVector ) ;
}

CipherStream.prototype = Object.create( Stream.Transform.prototype ) ;
CipherStream.prototype.constructor = CipherStream ;

helper.CipherStream = CipherStream ;



CipherStream.prototype._transform = function( buffer , encoding , callback ) {
	//log.hdebug( "Received %iB" , buffer.length ) ;
	if ( ! this.injectedHeader ) {
		this.push( this.initVector ) ;
		//log.hdebug( "Pushed %iB (init vector)" , this.initVector.length ) ;
		this.injectedHeader = true ;
	}

	// Encrypt the buffer
	buffer = this.cipher.update( buffer ) ;
	this.push( buffer ) ;
	//log.hdebug( "Pushed %iB (transform)" , buffer.length ) ;
	callback() ;
} ;



CipherStream.prototype._flush = function( callback ) {
	if ( ! this.injectedHeader ) {
		this.push( this.initVector ) ;
		this.injectedHeader = true ;
	}

	// Add remaining data...
	var buffer = this.cipher.final() ;
	if ( buffer.length ) { this.push( buffer ) ; }
	//log.hdebug( "Pushed %iB (flush)" , buffer.length ) ;
	callback() ;
} ;



function DecipherStream( userKey ) {
	Stream.Transform.call( this ) ;

	// Create the real cipher key from the user key/password
	this.cipherKey = helper.createCipherKey( userKey ) ;

	this.gotHeader = false ;
	this.initVector = null ;
	this.decipher = null ;
}

DecipherStream.prototype = Object.create( Stream.Transform.prototype ) ;
DecipherStream.prototype.constructor = DecipherStream ;

helper.DecipherStream = DecipherStream ;



DecipherStream.prototype._transform = function( buffer , encoding , callback ) {
	if ( ! this.gotHeader ) {
		// /!\ And what if it's not long enough?
		this.initVector = buffer.slice( 0 , 16 ) ;
		buffer = buffer.slice( 16 , Infinity ) ;
		this.decipher = crypto.createDecipheriv( algorithm , this.cipherKey , this.initVector ) ;
		this.gotHeader = true ;
	}

	// Encrypt the buffer
	this.push( this.decipher.update( buffer ) ) ;
	callback() ;
} ;



DecipherStream.prototype._flush = function( callback ) {
	if ( ! this.gotHeader ) {
		callback() ;
		return ;
	}

	// Add remaining data...
	this.push( this.decipher.final() ) ;
	callback() ;
} ;

