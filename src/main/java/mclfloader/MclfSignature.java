package mclfloader;

import java.io.IOException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class MclfSignature implements StructConverter {
	int modulusLength;
	byte[] modulus;
	int publicExponentLength;
	byte[] publicExponent;
	byte[] signature;

	public MclfSignature(MclfHeader header, BinaryReader reader) throws IOException
	{
		long totalLength 	= reader.length();
		long payloadLength 	= header.text.len + header.data.len;

		if ( totalLength > payloadLength ) {
			reader.setPointerIndex(payloadLength);

			modulusLength 			= reader.readNextInt();
			modulus 				= reader.readNextByteArray(modulusLength);
			publicExponentLength 	= reader.readNextInt();
			publicExponent 			= reader.readNextByteArray(publicExponentLength);
			signature 				= reader.readNextByteArray(256);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("MclfSignature", 0);

		structure.add(DWORD, 4, "modulusLength", null);
		structure.add(BYTE, modulusLength, "modulus", null);
		structure.add(DWORD, 4, "publicExponentLength", null);
		structure.add(BYTE, publicExponentLength, "publicExponent", null);
		structure.add(BYTE, 256, "signature", null);

		return structure;
	}
}
