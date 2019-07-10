package mclfloader;

import java.io.IOException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class MclfHeapSize implements StructConverter {
	public int init;
	public int max;
	
	public MclfHeapSize(BinaryReader reader) throws IOException
	{
		init 	= reader.readNextInt();
		max 	= reader.readNextInt();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("MclfHeapSize", 0);

		structure.add(DWORD, 4, "init", null);
		structure.add(DWORD, 4, "max", null);
		
		return structure;
	}
}
