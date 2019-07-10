package mclfloader;

import java.io.IOException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class MclfHeader implements StructConverter {
	final static int HEADER_SIZE_V1 	= 72;	// 0x0048
	final static int HEADER_SIZE_V2 	= 76;	// 0x004C
	final static int HEADER_SIZE_V23 	= 128;	// 0x0080
	final static int TEXT_HEADER_SIZE 	= 40;	// 0x0028
	
	// v2.0+ fields
	public MclfIntro 				intro;
	public int 						flags;
	public int 						memType;
	public int 						serviceType;
	public int 						numInstances;
	public MclfUuid 				uuid;
	public int 						driverId;
	public int 						numThreads;
	public MclfSegmentDescriptor 	text;
	public MclfSegmentDescriptor 	data;
	public int 						bssLen;
	public int 						entry;
	public int 						serviceVersion;
	
	// v2.3+ fields
	public MclfSuid 				permittedSuid;
	public int 						permittedHwCfg;
	
	// v2.4+ fields
	public int 						gp_level;
	public int 						attestationOffset;
	
	// filler for reserved/missing fields in older versions
	protected byte[] 				reserved;
	
	public MclfHeader(BinaryReader reader) throws IOException
	{
		intro 			= new MclfIntro(reader);
		flags 			= reader.readNextInt();
		memType 		= reader.readNextInt();
		serviceType 	= reader.readNextInt();
		numInstances 	= reader.readNextInt();		
		uuid 			= new MclfUuid(reader);
		driverId 		= reader.readNextInt();		
		numThreads 		= reader.readNextInt();	
		text 			= new MclfSegmentDescriptor(reader);
		data 			= new MclfSegmentDescriptor(reader);
		bssLen			= reader.readNextInt();
		entry			= reader.readNextInt();
		serviceVersion	= reader.readNextInt();
		
		if (intro.versionMajor() == 2 && intro.versionMinor() >= 3) {
			permittedSuid 	= new MclfSuid(reader);
			permittedHwCfg 	= reader.readNextInt();
			
			if (intro.versionMinor() >= 4) {
				gp_level 			= reader.readNextInt();
				attestationOffset 	= reader.readNextInt();
			}
		}

		reserved = reader.readNextByteArray((int) (headerSize() - reader.getPointerIndex()));
	}
	
	public long headerSize() {
		if (intro.versionMajor() == 2) {
			if (intro.versionMinor() >= 3 ) {
				return HEADER_SIZE_V23;
			}
		}
		
		return HEADER_SIZE_V2;
	}
	

	String serviceTypeName()
	{
		switch( serviceType )
		{
			case 0:		return "Illegal";
			case 1:		return "Driver";
			case 2:		return "SP Trustlet";
			case 3:		return "System Trustlet";
			case 4:		return "Middleware";
			default:	break;
		}

		return "Unknown";
	}
	
	String memoryTypeName()
	{
		switch( memType )
		{
			case 0:		return "Internal Preferred";
			case 1:		return "Internal";
			case 2:		return "External";
			default:	break;
		}
	
		return "Unknown";
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("MclfHeader", 0);

		structure.add(intro.toDataType(), intro.toDataType().getLength(), "intro", null);

		structure.add(DWORD, 4, "flags", null);
		structure.add(DWORD, 4, "memType", null);
		structure.add(DWORD, 4, "serviceType", null);
		structure.add(DWORD, 4, "numInstances", null);
		structure.add(uuid.toDataType(), uuid.toDataType().getLength(), "uuid", null);
		structure.add(DWORD, 4, "driverId", null);
		structure.add(DWORD, 4, "numThreads", null);
		structure.add(DWORD, 4, "numInstances", null);
		structure.add(text.toDataType(), text.toDataType().getLength(), "text", null);
		structure.add(text.toDataType(), text.toDataType().getLength(), "data", null);
		structure.add(DWORD, 4, "bssLen", null);
		structure.add(DWORD, 4, "entry", null);
		structure.add(DWORD, 4, "serviceVersion", null);

		if (intro.versionMajor() == 2 && intro.versionMinor() >= 3) {
			structure.add(permittedSuid.toDataType(), permittedSuid.toDataType().getLength(), "permittedSuid", null);
			structure.add(DWORD, 4, "permittedHwCfg", null);

			if (intro.versionMinor() >= 4) {
				structure.add(DWORD, 4, "gp_level", null);
				structure.add(DWORD, 4, "attestationOffset", null);
			}
		}
		
		//structure.add(BYTE, reserved.length, "reserved", null);

		return structure;
	}

	public boolean isDriver() {
		return serviceType == 1;
	}

	public boolean isSPTrustlet() {
		return serviceType == 2;
	}

	public boolean isSystemTrustlet() {
		return serviceType == 3;
	}

	public boolean isMiddleware() {
		return serviceType == 4;
	}

	public int serviceVersionMajor() {
		return serviceVersion >> 16 & 0xFFFF;
	}

	public int serviceVersionMinor() {
		return serviceVersion & 0xFFFF;
	}
}
