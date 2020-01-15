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



const JsPak = require( './JsPak.js' ) ;

const fsPromise = require( 'fs' ).promises ;
const termkit = require( 'terminal-kit' ) ;
const term = termkit.terminal ;

const cliManager = require( 'utterminal' ).cli ;
const package_ = require( '../package.json' ) ;



async function cli() {
	var jsPak ;

	/* eslint-disable indent */
	cliManager.package( package_ )
		.app( 'JsPak' )
		.description( "JsPak archiver." )
		//.usage( "[--option1] [--option2] [...]" )
		//.introIfTTY
		//.helpOption
		.commonOptions
		.camel
		.commonCommands
		.commandRequired

		.command( [ 'create' , 'c' ] )
			.usage( "<archive> [file1|directory1] [file2|directory2] [...] [--option1] [--option2] [...]" )
			.description( "It creates a new archive." )
			.arg( 'archive' ).string.mandatory
				.typeLabel( 'archive' )
				.description( "The archive file" )
			.restArgs( 'files' ).string.mandatory
				.typeLabel( 'files' )
				.description( "The files to add to the archive." )
			.option( [ 'gzip' , 'z' ] ).boolean
				.description( "Gzip the files" )
		.command( [ 'add' , 'a' ] )
			.usage( "<archive> [file1|directory1] [file2|directory2] [...] [--option1] [--option2] [...]" )
			.description( "It add files to an existing archive." )
			.arg( 'archive' ).string.mandatory
				.typeLabel( 'archive' )
				.description( "The archive file" )
			.restArgs( 'files' ).string.mandatory
				.typeLabel( 'files' )
				.description( "The files to add to the archive." )
			.option( [ 'gzip' , 'z' ] ).boolean
				.description( "Gzip the files" )
		.command( [ 'extract' , 'x' ] )
			.usage( "<archive> [toDirectory] [--option1] [--option2] [...]" )
			.description( "It extracts every files from the archive." )
			.arg( 'archive' ).string.mandatory
				.typeLabel( 'archive' )
				.description( "The archive file" )
			.arg( 'toDirectory' , process.cwd() ).string
				.typeLabel( 'directory' )
				.description( "The directory where to extract" )
		.command( [ 'list' , 'l' ] )
			.usage( "<archive> [--option1] [--option2] [...]" )
			.description( "It list all files in the archive." )
			.arg( 'archive' ).string.mandatory
				.typeLabel( 'archive' )
				.description( "The archive file" ) ;
	/* eslint-enable indent */

	var args = cliManager.run() ;
	term( "%n\n" , args ) ;

	switch ( args.command ) {
		case 'create' :
			jsPak = new JsPak( args.archive ) ;
			try {
				await jsPak.open( true ) ;
				await jsPak.add( args.files , { gzip: args.gzip } ) ;
			}
			catch ( error ) {
				term.red( "%s\n" , error ) ;
				term.red( "%E\n" , error ) ;
			}
			break ;

		case 'add' :
			jsPak = new JsPak( args.archive ) ;
			try {
				await jsPak.open( false ) ;
				await jsPak.add( args.files , { gzip: args.gzip } ) ;
			}
			catch ( error ) {
				term.red( "%s\n" , error ) ;
				term.red( "%E\n" , error ) ;
			}
			break ;

		case 'extract' :
			jsPak = new JsPak( args.archive ) ;
			try {
				await jsPak.open( false ) ;
				await jsPak.extract( args.toDirectory ) ;
			}
			catch ( error ) {
				term.red( "%s\n" , error ) ;
				term.red( "%E\n" , error ) ;
			}
			break ;

		case 'list' :
			jsPak = new JsPak( args.archive ) ;
			try {
				await jsPak.open( false ) ;
				await jsPak.load() ;
			}
			catch ( error ) {
				term.red( "%s\n" , error ) ;
				term.red( "%E\n" , error ) ;
			}

			for ( let entry of jsPak.map ) {
				term( "%s\n" , entry[ 0 ] ) ;
			}
			break ;
	}
}

module.exports = cli ;

