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



const cliManager = require( 'utterminal' ).cli ;
const package_ = require( '../package.json' ) ;
const JsPak = require( './JsPak.js' ) ;



async function cli() {
	var jsPak ;
	
	/* eslint-disable indent */
	cliManager.package( package_ )
		.app( package_.name )
		.description( "JS Pak archiver." )
		//.usage( "[--option1] [--option2] [...]" )
		//.introIfTTY
		//.helpOption
		.commonOptions
		.camel
		.commonCommands
		.commandRequired

		.command( [ 'create' , 'c' ] )
			//.usage( "[<book>] [--option1] [--option2] [...]" )
			//.description( "It starts playing a story book." )
			.arg( 'archive' ).string
				.typeLabel( 'archive' )
				.description( "The archive file (default to ./book)" )
			//.opt( 'load' ).string
			//	.typeLabel( 'file' )
			//	.description( "Load a previously saved game" )
	/* eslint-enable indent */

	var args = cliManager.run() ;
	
	if ( args.command === 'create' ) {
		jsPak = new JsPak( args.archive ) ;
		await jsPak.open() ;
	}
}

module.exports = cli ;

