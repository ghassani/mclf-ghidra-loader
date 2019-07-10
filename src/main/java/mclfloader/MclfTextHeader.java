package mclfloader;

import java.io.IOException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class MclfTextHeader implements StructConverter {
	public int 						version;
	public int 						textHeaderLen;
	public int 						requiredFeat;
	public int 						mcLibEntry;
	public MclfIMD 					mcIMD;
	public int 						tlApiVers;
	public int 						drApiVers;
	public int 						ta_properties;

	public MclfTextHeader(MclfHeader header, BinaryReader reader) throws IOException {
		version 			= reader.readNextInt();
		textHeaderLen 		= reader.readNextInt();
		requiredFeat 		= reader.readNextInt();
		mcLibEntry 			= reader.readNextInt();
		mcIMD 				= new MclfIMD(header, reader);
		tlApiVers 			= reader.readNextInt();
		drApiVers 			= reader.readNextInt();
		ta_properties 		= reader.readNextInt();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("MclfTextHeader", 0);

		structure.add(DWORD, 4, "version", null);
		structure.add(DWORD, 4, "textHeaderLen", null);
		structure.add(DWORD, 4, "requiredFeat", null);
		structure.add(DWORD, 4, "mcLibEntry", null);
		structure.add(mcIMD.toDataType(), mcIMD.toDataType().getLength(), "mcIMD", null);	
		structure.add(DWORD, 4, "tlApiVers", null);
		structure.add(DWORD, 4, "drApiVers", null);
		structure.add(DWORD, 4, "ta_properties", null);
		
		return structure;
	}
}