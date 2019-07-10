package mclfloader;

import java.io.IOException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class MclfSegmentDescriptor implements StructConverter {
	public int start;
	public int len;
	
	public MclfSegmentDescriptor(BinaryReader reader) throws IOException
	{
		start 	= reader.readNextInt();
		len 	= reader.readNextInt();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("MclfSegmentDescriptor", 0);

		structure.add(DWORD, 4, "start", null);
		structure.add(DWORD, 4, "len", null);
		
		return structure;
	}
}
