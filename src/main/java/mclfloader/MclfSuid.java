package mclfloader;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class MclfSuid  implements StructConverter {
	public static final int MC_SUID_LEN  =  16;
	
	int sipId;
	byte[] suidData;
	
	public MclfSuid(BinaryReader reader) throws IOException
	{
		sipId 		= reader.readNextInt();
		suidData 	= reader.readNextByteArray(MC_SUID_LEN - 4);
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("MclfSuid", 0);

		structure.add(DWORD, 4, "sipId", null);
		structure.add(BYTE, MC_SUID_LEN - 4, "suidData", null);
		
		return structure;
	}
	
}
