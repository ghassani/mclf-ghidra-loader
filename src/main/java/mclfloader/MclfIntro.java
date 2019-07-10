package mclfloader;

import java.io.IOException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class MclfIntro implements StructConverter {
	final int MCLF_MAGIC_BE = 0x4D434C46;
	final int MCLF_MAGIC_LE = 0x464C434D;
	
	public int magic;
	public int version;
	
	public MclfIntro(BinaryReader reader) throws IOException {
		magic = reader.readNextInt();
		
		if (!isValid()) {
			return;
		}
		
		version = reader.readNextInt();
		
		if (magic == MCLF_MAGIC_BE) {
			reader.setLittleEndian(false);
		}
	}
	
	public int versionMajor() {
		return version >> 16;
	}
	
	public int versionMinor() {
		return version & 0xFFFF;
	}
	
	public boolean isValid() {
		return magic == MCLF_MAGIC_LE || magic == MCLF_MAGIC_BE;
	}
	
	public boolean isLittleEndian() {
		return isValid() && magic == MCLF_MAGIC_LE;
	}
	
	public boolean isBigEndian() {
		return isValid() && magic == MCLF_MAGIC_BE;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("MclfIntro", 0);
		
		structure.add(STRING, 4, "magic", null);
		structure.add(DWORD, 4, "version", null);
		
		return structure;
	}
}
