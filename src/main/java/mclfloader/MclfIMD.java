package mclfloader;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class MclfIMD  implements StructConverter {
	
	public MclfSegmentDescriptor 	mcLibData;
	public MclfHeapSize 			heapSize;
	public int 						mcLibBase;

	public MclfIMD(MclfHeader header, BinaryReader reader) throws IOException
	{
		if (header.intro.versionMinor() >= 5 ) {
			heapSize = new MclfHeapSize(reader);
		} else {
			mcLibData = new MclfSegmentDescriptor(reader);
		}
		
		mcLibBase 	= reader.readNextInt();
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("MclfIMD", 0);

		if ( mcLibData != null ) {
			structure.add(mcLibData.toDataType(), mcLibData.toDataType().getLength(), "mcLibData", null);
		} else if ( heapSize != null) {
			structure.add(heapSize.toDataType(), heapSize.toDataType().getLength(), "heapSize", null);
		}
		
		structure.add(DWORD, 4, "mcLibBase", null);
		
		return structure;
	}
	
}
