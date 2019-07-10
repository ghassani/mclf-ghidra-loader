/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package mclfloader;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.MemoryBlockUtil;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;

import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;

import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;

import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class MclfLoader extends AbstractLibrarySupportLoader {

	final int MCLF_VA_BASE 					= 0x0000;	
	final int MCLF_PAGE_SIZE 				= 0x1000;	
	final int MCLF_MIN_SUPPORTED_VERSION 	= 2;
	final int MCLIB_ENTRY_PTR_OFFSET		= 0x108c;

	@Override
	public String getName() {
		return "MCLF Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		BinaryReader 	reader;
		MclfIntro 		intro;
		
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		if ( provider.length() < 8 ) {
			return loadSpecs;
		}
		
		reader 	= new BinaryReader(provider, true);
		intro 	= new MclfIntro(reader);
		
		if (!intro.isValid()) {
			return loadSpecs;
		} else if (intro.versionMajor() > MCLF_MIN_SUPPORTED_VERSION) {
			return loadSpecs;
		}
		
		if (intro.isBigEndian()) {
			loadSpecs.add(new LoadSpec(this, MCLF_VA_BASE, new LanguageCompilerSpecPair("ARM:BE:32:v8", "default"), true));
		} else {
			loadSpecs.add(new LoadSpec(this, MCLF_VA_BASE, new LanguageCompilerSpecPair("ARM:LE:32:v8", "default"), true));
		}
				
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		
		BinaryReader 	reader 		= new BinaryReader(provider, true);
		MclfHeader 		header 		= new MclfHeader(reader);
		MclfTextHeader	textHeader	= new MclfTextHeader(header, reader);
		MclfSignature	signature  	= null;
		MemoryBlockUtil mbu 		= new MemoryBlockUtil(program, handler);
		AddressSpace 	space 		= program.getAddressFactory().getDefaultAddressSpace();		
		
		try {
			signature = new MclfSignature(header, reader);
		} catch (IOException e) {

		}

		logHeaderDetails(header, textHeader, signature, log);
		createDataTypes(program, header, textHeader, signature);
		createTextSegment(provider, space, mbu, header, monitor, log);
		createDataSegment(provider, space, mbu, header, monitor, log);
		createBssSegment(provider, space, mbu, header, monitor, log);

		// set known data types
		try {
			program.getListing().createData(space.getAddress(header.text.start), header.toDataType(), header.toDataType().getLength());
			program.getListing().createData(space.getAddress(header.text.start + header.headerSize()), textHeader.toDataType(), textHeader.toDataType().getLength());
		} catch (CodeUnitInsertionException | DataTypeConflictException | AddressOutOfBoundsException | DuplicateNameException e) {
			e.printStackTrace();
		}

		Address entryAddr 	= space.getAddress(header.entry);
		String entryName 	= "tl_entry";

		if ( header.isDriver() ) entryName = "dr_entry";

		try {
			program.getSymbolTable().addExternalEntryPoint(entryAddr);
			program.getSymbolTable().createLabel(entryAddr, entryName, SourceType.ANALYSIS);
			program.getSymbolTable().createLabel(space.getAddress(MCLIB_ENTRY_PTR_OFFSET), "mcLibEntry", SourceType.ANALYSIS);
		} catch (InvalidInputException e) {
			e.printStackTrace();
		}

		try {
			program.getFunctionManager().createFunction(entryName, entryAddr, new AddressSet(entryAddr), SourceType.IMPORTED);
		} catch (InvalidInputException | OverlappingFunctionException e) {
			e.printStackTrace();
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
		
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options) {
		return super.validateOptions(provider, loadSpec, options);
	}
	
	/**
	 * pageAlign
	 * 
	 * @param value
	 * @return
	 */
	protected long pageAlign(long value) {	
		return value + ( MCLF_PAGE_SIZE - ( value % MCLF_PAGE_SIZE ) );
	}
	
	/**
	 * createDataTypes
	 * 
	 * @param program
	 * @param header
	 * @param textHeader
	 */
	protected void createDataTypes(Program program, MclfHeader header, MclfTextHeader textHeader, MclfSignature signature) {
		try {
			program.getDataTypeManager().addDataType(header.toDataType(), null);
			program.getDataTypeManager().addDataType(textHeader.toDataType(), null);

			if (signature != null) {
				program.getDataTypeManager().addDataType(signature.toDataType(), null);
			}
		} catch (DuplicateNameException | IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * createTextSegment
	 * 
	 * @param provider
	 * @param space
	 * @param mbu
	 * @param header
	 * @param monitor
	 * @param log
	 */
	protected void createTextSegment(ByteProvider provider, AddressSpace space, MemoryBlockUtil mbu, MclfHeader header, TaskMonitor monitor, MessageLog log) {
		long start 			= header.text.start;
		long end 			= header.text.start + header.text.len;
		long endaligned 	= pageAlign(end);
		long cavesize 		= ( endaligned > end ) ? ( endaligned - end ) : 0;

		try {
			mbu.createInitializedBlock(".text", space.getAddress(start), provider.getInputStream(0), header.text.len, "", "", true, false, true, monitor);
			
			if ( cavesize > 0 ) {
				mbu.createUninitializedBlock(false, ".text_cave", space.getAddress(end), cavesize, "", "", true, false, true);
			}
		} catch (AddressOverflowException | AddressOutOfBoundsException | IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * createDataSegment
	 * 
	 * @param provider
	 * @param space
	 * @param mbu
	 * @param header
	 * @param monitor
	 * @param log
	 */
	protected void createDataSegment(ByteProvider provider, AddressSpace space, MemoryBlockUtil mbu, MclfHeader header, TaskMonitor monitor, MessageLog log) {
		long start 			= header.data.start;
		long end 			= header.data.start + header.data.len;
		long endaligned 	= pageAlign(end);
		long datalen	 	= header.data.len;
		long segsend	 	= header.text.len + header.data.len;
		long cavesize 		= ( endaligned > end ) ? ( endaligned - end ) : 0;
		long remainder		= 0;

		try {
			/*if (segsend < provider.length()) {
				remainder 		= provider.length() - segsend;
				end 			+= remainder;
				datalen 		+= remainder;
				endaligned 		= pageAlign(end);
				cavesize 		= ( endaligned > end ) ? ( endaligned - end ) : 0;
			}*/

			mbu.createInitializedBlock(".data", space.getAddress(start), provider.getInputStream(header.text.len), datalen, "", "", true, true, false, monitor);
			
			if ( cavesize > 0 ) {
				mbu.createUninitializedBlock(false, ".data_cave", space.getAddress(end), cavesize, "", "", true, true, false);
			}

		} catch (AddressOverflowException | AddressOutOfBoundsException | IOException e) {
			e.printStackTrace();
		}
	}

	protected void createBssSegment(ByteProvider provider, AddressSpace space, MemoryBlockUtil mbu, MclfHeader header, TaskMonitor monitor, MessageLog log) {
		mbu.createUninitializedBlock(false, ".bss", space.getAddress(pageAlign(header.data.start + header.data.len)), header.bssLen, "", "", true, true, true);	
	}

	protected void logHeaderDetails(MclfHeader header, MclfTextHeader textHeader, MclfSignature	signature, MessageLog log) {
		log.appendMsg(String.format("MCLF Header v%d.%d", header.intro.versionMajor(), header.intro.versionMinor()));
		log.appendMsg(String.format("Flags: 0x%04X", header.flags));
		log.appendMsg(String.format("Memory Type: %s [%d]", header.memoryTypeName(), header.memType));
		log.appendMsg(String.format("Service Type: %s [%d]", header.serviceTypeName(), header.serviceType));
		log.appendMsg(String.format("Number of Instances: %d", header.numInstances));		
		log.appendMsg(String.format("UUID: %s", bytesToHexString(header.uuid.value)));		
		log.appendMsg(String.format("Driver ID: 0x%04X", header.driverId));
		log.appendMsg(String.format("Threads: %d", header.numThreads));
		log.appendMsg(String.format("Text VA: 0x%04X", header.text.start));
		log.appendMsg(String.format("Text Length: %d", header.text.len));
		log.appendMsg(String.format("Data VA: 0x%04X", header.data.start));
		log.appendMsg(String.format("Data Length: %d", header.data.len));
		log.appendMsg(String.format("BSS Length: %d", header.bssLen));
		log.appendMsg(String.format("Entry: 0x%04X", header.entry));
		log.appendMsg(String.format("Service Version: %d v%d.%d", header.serviceVersion, header.serviceVersionMajor(), header.serviceVersionMinor()));
		
		if ( header.intro.versionMajor() == 2 ) {
			if ( header.intro.versionMinor() >= 3 ) {
				log.appendMsg(String.format("Permitted SUID SIP ID: 0x%04X", header.permittedSuid.sipId));
				log.appendMsg(String.format("Permitted SUID Data: %s", bytesToHexString(header.permittedSuid.suidData)));
				log.appendMsg(String.format("Permitted HW Config: 0x%04X", header.permittedHwCfg));
			}
			
			if ( header.intro.versionMinor() >= 4 ) {
				log.appendMsg(String.format("gp_level: 0x%04X", header.gp_level));
				log.appendMsg(String.format("attestationOffset: 0x%04X", header.attestationOffset));
			}
		}
		
		log.appendMsg("== TEXT Header Info ==");
		log.appendMsg(String.format("Version: 0x%04X", textHeader.version));
		log.appendMsg(String.format("Text Header Length: %d", textHeader.textHeaderLen));
		log.appendMsg(String.format("Required Features: 0x%04X", textHeader.requiredFeat));
		log.appendMsg(String.format("McLib Entry: 0x%04X", textHeader.mcLibEntry));
		log.appendMsg(String.format("Required Features: 0x%04X", textHeader.requiredFeat));

		if ( header.intro.versionMinor() >= 5 ) {
			log.appendMsg(String.format("Heap Size Init: 0x%04X", textHeader.mcIMD.heapSize.init));
			log.appendMsg(String.format("Heap Size Max: 0x%04X", textHeader.mcIMD.heapSize.max));
		} else {
			log.appendMsg(String.format("Header:mcLibData Start: 0x%04X", textHeader.mcIMD.mcLibData.start));
			log.appendMsg(String.format("Header:mcLibData Size: 0x%04X", textHeader.mcIMD.mcLibData.len));
		}
		
		log.appendMsg(String.format("mcLib Base: 0x%04X", textHeader.mcIMD.mcLibBase));
		log.appendMsg(String.format("Trustlet API Version: 0x%04X", textHeader.tlApiVers));
		log.appendMsg(String.format("Driver API Version: 0x%04X", textHeader.drApiVers));
		log.appendMsg(String.format("ta_properties: 0x%04X", textHeader.ta_properties));

		if ( signature != null ) {
			log.appendMsg(String.format("Signature -> Start Offset: %d", header.text.len + header.data.len));
			log.appendMsg(String.format("Signature -> Modulus Length: %d", signature.modulusLength));
			log.appendMsg(String.format("Signature -> Modulus: %s", bytesToHexString(signature.modulus)));
			log.appendMsg(String.format("Signature -> Public Exponent Length: %d", signature.publicExponentLength));
			log.appendMsg(String.format("Signature -> Public Exponent: %s", bytesToHexString(signature.publicExponent)));
			log.appendMsg(String.format("Signature -> Hash: %s", bytesToHexString(signature.signature)));
		}
	}

	protected String bytesToHexString(byte[] in)
	{
		String ret = "";
		for ( int i = 0; i < in.length; i++ ) {
			ret = ret.concat(String.format("%02X", in[i]));
		}
		return ret;
	}
}
