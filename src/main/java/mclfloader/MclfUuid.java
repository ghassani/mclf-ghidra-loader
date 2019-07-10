package mclfloader;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class MclfUuid  implements StructConverter {
	final static int UUID_LENGTH 		= 16;
	
	byte[] value;
	
	public MclfUuid(BinaryReader reader) throws IOException
	{
		value = reader.readNextByteArray(UUID_LENGTH);
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("MclfUuid", 0);

		structure.add(BYTE, UUID_LENGTH, "value", null);
		
		return structure;
	}
	
}
