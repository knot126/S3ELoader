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
package s3eloader;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class S3ELoaderLoader extends AbstractProgramWrapperLoader {
	String[] ARCH_LANGUAGE_MAPPING = {
			// Note: Some of these are wrong/not seemingly supported by ghidra
			// and are mapped to their closest match
			"ARM:LE:32:v4t", // ARM4T
			"ARM:LE:32:v4", // ARM4
			"ARM:LE:32:v5t", // ARM5T
			"ARM:LE:32:v5t", // ARM5TE
			"ARM:LE:32:v5t", // ARM5TEJ
			"ARM:LE:32:v6", // ARM6
			"ARM:LE:32:v6", // ARM6K
			"ARM:LE:32:v6", // ARM6T2
			"ARM:LE:32:v6", // ARM6Z
			"x86:LE:64:default", // X86
			"PowerPC:LE:32:4xx", // PPC
			"x86:LE:64:default", // AMD64
			"x86:LE:64:default", // X86_64
			"ARM:LE:32:v7", // ARM7A
			"ARM:LE:32:v8", // ARM8A
			"AARCH64:LE:64:v8A", // ARM8A_AARCH64
			"x86:LE:64:default", // NACLX86_64
	};

	@Override
	public String getName() {

		// TODO: Name the loader.  This name must match the name of the loader in the .opinion 
		// files.

		return "S3ELoader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		BinaryReader br = new BinaryReader(provider, true);
		
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// TODO: Examine the bytes in 'provider' to determine if this loader can load it.  If it 
		// can load it, return the appropriate load specifications.
		//if (br.readNextByteArray(4) == (("XE3U").getBytes())) {
		//	loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:v6", "default"), true));
		//}
		
		int header = br.readNextInt();
		int version = br.readNextInt();
		short flags = br.readNextShort();
		short arch = br.readNextShort();
		
		if (header == 0x55334558) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(ARCH_LANGUAGE_MAPPING[arch], "default"), true));
		}
		
		// !! TODO !! We should find the header and read what arch to use

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		// TODO: Load the bytes from 'provider' into the 'program'.
		
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		
		Memory memory = program.getMemory();
		InputStream ist = provider.getInputStream(0);
		//SymbolTable symbols = program.getSymbolTable();
		//RelocationTable relocations = program.getRelocationTable();
		
		// read that sick s3e header
		BinaryReader br = new BinaryReader(provider, true);
		int header = br.readNextInt();
		int version = br.readNextInt();
		short flags = br.readNextShort();
		short arch = br.readNextShort();
		int fixupOffset = br.readNextInt();
		int fixupSize = br.readNextInt();
		int codeOffset = br.readNextInt();
		int codeFileSize = br.readNextInt();
		int codeMemSize = br.readNextInt();
		int sigOffset = br.readNextInt();
		int sigSize = br.readNextInt();
		int entryOffset = br.readNextInt();
		int configOffset = br.readNextInt();
		int configSize = br.readNextInt();
		long baseAddrOrig = br.readNextInt(); // this is a long since we need the full address range lmao
		int extraOffset = br.readNextInt();
		int extraSize = br.readNextInt();
		int extHeaderSize = br.readNextInt();
		
		boolean hasCodeDataSplit = false;
		int realCodeSize = 0;
		
		// TODO it's more complicated than this but should allow loading early and late s3e which
		// are currently what I really care about
		if (extHeaderSize <= 12) {
			hasCodeDataSplit = true;
			realCodeSize = br.readNextInt();
			int showSplash = br.readNextInt();
		}
		
		int bssSize = codeMemSize - codeFileSize;
		
		/**
		 * Load the program bytes into ghidra's representation of memory
		 */
		FileBytes fb = memory.createFileBytes(provider.getName(), 0, provider.length(), ist, monitor);
		
		try {
			if (hasCodeDataSplit) {
				MemoryBlock block = memory.createInitializedBlock("code", api.toAddr(baseAddrOrig), fb, codeOffset, realCodeSize, false);
				block.setRead(true);
				block.setWrite(false);
				block.setExecute(true);
				
				MemoryBlock data = memory.createInitializedBlock("data", api.toAddr(baseAddrOrig + realCodeSize), fb, codeOffset + realCodeSize, codeFileSize - realCodeSize, false);
				data.setRead(true);
				data.setWrite(true);
				data.setExecute(false);
			}
			else {
				MemoryBlock block = memory.createInitializedBlock("code+data", api.toAddr(baseAddrOrig), fb, codeOffset, codeFileSize, false);
				block.setRead(true);
				block.setWrite(true);
				block.setExecute(true);
			}
			
			MemoryBlock bss = memory.createInitializedBlock("bss", api.toAddr(baseAddrOrig + codeFileSize), bssSize, (byte) 0x0, monitor, false);
			bss.setRead(true);
			bss.setWrite(true);
			bss.setExecute(false);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		
		/**
		 * Read the load table.
		 */
		List<String> symbolNames = new ArrayList<>();
		br.setPointerIndex(fixupOffset);
		ExternalManager extman = program.getExternalManager();
		
		while (br.getPointerIndex() < (fixupOffset + fixupSize)) {
			int fixupSectionOffset = (int) br.getPointerIndex();
			int fixupSectionType = br.readNextInt();
			int fixupSectionSize = br.readNextInt() - 8;
			
			System.out.printf("fixup section type %d size 0x%x\n", fixupSectionType, fixupSectionSize);
			
			switch (fixupSectionType) {
				// Symbol names
				case 0: {
					int symbolCount = br.readNextShort();
					
					System.out.printf("Loading %d symbol names...\n", symbolCount);
					
					for (int i = 0; i < symbolCount; i++) {
						symbolNames.add(br.readNextAsciiString());
					}
					
					break;
				}
				
				// Internal relocations
				// Handling this seems to be unneeded...
				case 1: {
					/*long intRelocCount = br.readNextUnsignedInt();
					
					try {
						for (int i = 0; i < intRelocCount; i++) {
							long offset = br.readNextUnsignedInt();
							
							// HACK: dear god. ghidra doesn't let you read or write unsigned values. so here's a hack...
							long origVal = api.getInt(api.toAddr(baseAddrOrig + offset)) & 0xffffffffL;
							api.setInt(api.toAddr(baseAddrOrig + offset), (int) ((baseAddrOrig + origVal) & 0xffffffffL));
						}
					}
					catch (Exception e) {
						e.printStackTrace();
					}*/
					
					break;
				}
				
				// External relocations
				case 2:
				case 3:
				case 4: {
					int extRelocCount = br.readNextInt();
					
					try {
						for (int i = 0; i < extRelocCount; i++) {
							int hi = br.readNextUnsignedShort();
							int lo = br.readNextUnsignedShort();
							long offset = (hi << 16) | lo;
							int symbolIndex = br.readNextUnsignedShort();
							
							
							System.out.printf("create extref 0x%x (offset 0x%x) for %s\n", baseAddrOrig + offset, offset, symbolNames.get(symbolIndex));
							
							Data data = api.createDWord(api.toAddr(baseAddrOrig + offset));
							api.createExternalReference(data, "libs3e_android.so", symbolNames.get(symbolIndex), null);
						}
					}
					catch (Exception e) {
						e.printStackTrace();
					}
					
					break;
				}
				
				default: {
					break;
				}
			}
			
			br.setPointerIndex(fixupSectionOffset + fixupSectionSize + 8);
		}
		
		/**
		 * Finalise stuff
		 */
		api.addEntryPoint(api.toAddr(baseAddrOrig + entryOffset));
		api.disassemble(api.toAddr(baseAddrOrig + entryOffset));
		api.createFunction(api.toAddr(baseAddrOrig + entryOffset), "__s3e_app_main");
		
		ist.close();
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		//list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
