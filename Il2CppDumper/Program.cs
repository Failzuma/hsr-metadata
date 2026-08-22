using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Il2CppDumper
{
    class Program
    {
        private static Config config;
        private static RuntimeProfile runtimeProfile;
        private static string sidecarDirectory;

        [STAThread]
        static void Main(string[] args)
        {
            config = JsonSerializer.Deserialize<Config>(File.ReadAllText(AppDomain.CurrentDomain.BaseDirectory + @"config.json"));
            string il2cppPath = null;
            string metadataPath = null;
            string outputDir = null;

            for (int i = 0; i < args.Length; i++)
            {
                var arg = args[i];
                if (arg == "-h" || arg == "--help" || arg == "/?" || arg == "/h")
                {
                    ShowHelp();
                    return;
                }
                if (arg == "--code-reg" && i + 1 < args.Length)
                {
                    config.CodeRegistration = ParseUnsigned(args[++i]);
                    if (runtimeProfile != null)
                        runtimeProfile.CodeRegistrationVa = config.CodeRegistration;
                    continue;
                }
                if (arg == "--meta-reg" && i + 1 < args.Length)
                {
                    config.MetadataRegistration = ParseUnsigned(args[++i]);
                    if (runtimeProfile != null)
                        runtimeProfile.MetadataRegistrationVa = config.MetadataRegistration;
                    continue;
                }
                if (arg == "--runtime-profile" && i + 1 < args.Length)
                {
                    runtimeProfile = JsonSerializer.Deserialize<RuntimeProfile>(File.ReadAllText(args[++i]));
                    continue;
                }
                if (arg == "--method-pointers-va" && i + 1 < args.Length)
                {
                    GetRuntimeProfile().MethodPointersVa = ParseUnsigned(args[++i]);
                    continue;
                }
                if (arg == "--method-pointers-count" && i + 1 < args.Length)
                {
                    GetRuntimeProfile().MethodPointersCount = ParseCount(args[++i]);
                    continue;
                }
                if (arg == "--types-va" && i + 1 < args.Length)
                {
                    GetRuntimeProfile().TypesVa = ParseUnsigned(args[++i]);
                    continue;
                }
                if (arg == "--types-count" && i + 1 < args.Length)
                {
                    GetRuntimeProfile().TypesCount = ParseCount(args[++i]);
                    continue;
                }
                if (arg == "--types-layout" && i + 1 < args.Length)
                {
                    GetRuntimeProfile().TypesAreInline = ParseLayout(args[++i]);
                    continue;
                }
                if (arg == "--generic-insts-va" && i + 1 < args.Length)
                {
                    GetRuntimeProfile().GenericInstsVa = ParseUnsigned(args[++i]);
                    continue;
                }
                if (arg == "--generic-insts-count" && i + 1 < args.Length)
                {
                    GetRuntimeProfile().GenericInstsCount = ParseCount(args[++i]);
                    continue;
                }
                if (arg == "--generic-insts-layout" && i + 1 < args.Length)
                {
                    GetRuntimeProfile().GenericInstsAreInline = ParseLayout(args[++i]);
                    continue;
                }
                if (arg == "--generic-class-count" && i + 1 < args.Length)
                {
                    GetRuntimeProfile().GenericClassCount = ParseCount(args[++i]);
                    continue;
                }
                if (arg == "--sidecar-dir" && i + 1 < args.Length)
                {
                    sidecarDirectory = Path.GetFullPath(args[++i]);
                    continue;
                }
                if (File.Exists(arg))
                {
                    var file = File.ReadAllBytes(arg);
                    if (file.Length >= 4 && BitConverter.ToUInt32(file, 0) == 0xFAB11BAF)
                    {
                        metadataPath = arg;
                    }
                    else
                    {
                        il2cppPath = arg;
                    }
                }
                else if (Directory.Exists(arg))
                {
                    outputDir = Path.GetFullPath(arg) + Path.DirectorySeparatorChar;
                }
                else if (il2cppPath != null && metadataPath != null && !arg.StartsWith("-"))
                {
                    outputDir = Path.GetFullPath(arg) + Path.DirectorySeparatorChar;
                    Directory.CreateDirectory(outputDir);
                }
            }
            outputDir ??= AppDomain.CurrentDomain.BaseDirectory;
            sidecarDirectory ??= metadataPath == null ? null : Path.GetDirectoryName(Path.GetFullPath(metadataPath));
            if (runtimeProfile != null)
            {
                if (runtimeProfile.CodeRegistrationVa != 0)
                    config.CodeRegistration = runtimeProfile.CodeRegistrationVa;
                if (runtimeProfile.MetadataRegistrationVa != 0)
                    config.MetadataRegistration = runtimeProfile.MetadataRegistrationVa;
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (il2cppPath == null)
                {
                    var ofd = new OpenFileDialog
                    {
                        Filter = "Il2Cpp binary file|*.*"
                    };
                    if (ofd.ShowDialog())
                    {
                        il2cppPath = ofd.FileName;
                        ofd.Filter = "global-metadata|global-metadata.dat";
                        if (ofd.ShowDialog())
                        {
                            metadataPath = ofd.FileName;
                        }
                        else
                        {
                            return;
                        }
                    }
                    else
                    {
                        return;
                    }
                }
            }
            if (il2cppPath == null)
            {
                ShowHelp();
                return;
            }
            if (metadataPath == null)
            {
                Console.WriteLine($"ERROR: Metadata file not found or encrypted.");
            }
            else
            {
                try
                {
                    if (Init(il2cppPath, metadataPath, out var metadata, out var il2Cpp))
                    {
                        Dump(metadata, il2Cpp, outputDir);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            }
            if (config.RequireAnyKey)
            {
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey(true);
            }
        }

        static void ShowHelp()
        {
            Console.WriteLine($"usage: {AppDomain.CurrentDomain.FriendlyName} <executable-file> <global-metadata> <output-directory> [--runtime-profile <json>] [--sidecar-dir <directory>] [runtime table overrides]");
            Console.WriteLine("runtime table overrides:");
            Console.WriteLine("  --code-reg <va> --meta-reg <va>");
            Console.WriteLine("  --method-pointers-va <va> --method-pointers-count <count>");
            Console.WriteLine("  --types-va <va> --types-count <count> --types-layout <inline|pointers>");
            Console.WriteLine("  --generic-insts-va <va> --generic-insts-count <count> --generic-insts-layout <inline|pointers>");
            Console.WriteLine("  --generic-class-count <count>");
        }

        private static RuntimeProfile GetRuntimeProfile()
        {
            return runtimeProfile ??= new RuntimeProfile();
        }

        private static ulong ParseUnsigned(string value)
        {
            return value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                ? Convert.ToUInt64(value.Substring(2), 16)
                : Convert.ToUInt64(value, 10);
        }

        private static long ParseCount(string value)
        {
            return checked((long)ParseUnsigned(value));
        }

        private static bool ParseLayout(string value)
        {
            if (value.Equals("inline", StringComparison.OrdinalIgnoreCase))
                return true;
            if (value.Equals("pointers", StringComparison.OrdinalIgnoreCase))
                return false;
            throw new ArgumentException($"Unknown runtime table layout: {value}");
        }

        private static bool Init(string il2cppPath, string metadataPath, out Metadata metadata, out Il2Cpp il2Cpp)
        {
            Console.WriteLine("Initializing metadata...");
            var metadataBytes = File.ReadAllBytes(metadataPath);
            metadata = new Metadata(new MemoryStream(metadataBytes));
            Console.WriteLine($"Metadata Version: {metadata.Version}");
            Console.WriteLine($"Metadata ParameterDefs: {metadata.parameterDefs?.Length}, MethodDefs: {metadata.methodDefs?.Length}, TypeDefs: {metadata.typeDefs?.Length}");

            Console.WriteLine("Initializing il2cpp file...");
            var il2cppBytes = File.ReadAllBytes(il2cppPath);
            var il2cppMagic = BitConverter.ToUInt32(il2cppBytes, 0);
            var il2CppMemory = new MemoryStream(il2cppBytes);
            if ((il2cppMagic & 0xFFFF) == 0x5A4D)
            {
                il2Cpp = new PE(il2CppMemory);
            }
            else
            {
                switch (il2cppMagic)
                {
                    default:
                        throw new NotSupportedException("ERROR: il2cpp file not supported.");
                    case 0x6D736100:
                        var web = new WebAssembly(il2CppMemory);
                        il2Cpp = web.CreateMemory();
                        break;
                    case 0x304F534E:
                        var nso = new NSO(il2CppMemory);
                        il2Cpp = nso.UnCompress();
                        break;
                    case 0x905A4D: //PE
                        il2Cpp = new PE(il2CppMemory);
                        break;
                case 0x464c457f: //ELF
                    if (il2cppBytes[4] == 2) //ELF64
                    {
                        il2Cpp = new Elf64(il2CppMemory);
                    }
                    else
                    {
                        il2Cpp = new Elf(il2CppMemory);
                    }
                    break;
                case 0xCAFEBABE: //FAT Mach-O
                case 0xBEBAFECA:
                    var machofat = new MachoFat(new MemoryStream(il2cppBytes));
                    Console.Write("Select Platform: ");
                    for (var i = 0; i < machofat.fats.Length; i++)
                    {
                        var fat = machofat.fats[i];
                        Console.Write(fat.magic == 0xFEEDFACF ? $"{i + 1}.64bit " : $"{i + 1}.32bit ");
                    }
                    Console.WriteLine();
                    var key = Console.ReadKey(true);
                    var index = int.Parse(key.KeyChar.ToString()) - 1;
                    var magic = machofat.fats[index % 2].magic;
                    il2cppBytes = machofat.GetMacho(index % 2);
                    il2CppMemory = new MemoryStream(il2cppBytes);
                    if (magic == 0xFEEDFACF)
                        goto case 0xFEEDFACF;
                    else
                        goto case 0xFEEDFACE;
                case 0xFEEDFACF: // 64bit Mach-O
                    il2Cpp = new Macho64(il2CppMemory);
                    break;
                case 0xFEEDFACE: // 32bit Mach-O
                    il2Cpp = new Macho(il2CppMemory);
                    break;
                }
            }
            var version = config.ForceIl2CppVersion ? config.ForceVersion : metadata.Version;
            il2Cpp.SetProperties(version, metadata.metadataUsagesCount);
            il2Cpp.SetRuntimeProfile(runtimeProfile, sidecarDirectory);
            Console.WriteLine($"Il2Cpp Version: {il2Cpp.Version}");
            if (config.ForceDump || il2Cpp.CheckDump())
            {
                if (il2Cpp is ElfBase elf)
                {
                    Console.WriteLine("Detected this may be a dump file.");
                    Console.WriteLine("Input il2cpp dump address or input 0 to force continue:");
                    var DumpAddr = Convert.ToUInt64(Console.ReadLine(), 16);
                    if (DumpAddr != 0)
                    {
                        il2Cpp.ImageBase = DumpAddr;
                        il2Cpp.IsDumped = true;
                        if (!config.NoRedirectedPointer)
                        {
                            elf.Reload();
                        }
                    }
                }
                else
                {
                    il2Cpp.IsDumped = true;
                }
            }

            Console.WriteLine("Searching...");
            try
            {
                var flag = false;
                if (config.CodeRegistration != 0 && config.MetadataRegistration != 0)
                {
                    il2Cpp.Init(config.CodeRegistration, config.MetadataRegistration);
                    flag = true;
                }
                if (!flag)
                {
                    try { flag = il2Cpp.PlusSearch(metadata.methodDefs.Count(x => x.methodIndex >= 0), metadata.typeDefs.Length, metadata.imageDefs.Length); } catch {}
                }
                if (!flag && !il2Cpp.IsDumped && RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && il2Cpp is PE)
                {
                    try
                    {
                        Console.WriteLine("Use custom PE loader");
                        var peLoader = PELoader.Load(il2cppPath);
                        peLoader.SetProperties(version, metadata.metadataUsagesCount);
                        peLoader.SetRuntimeProfile(runtimeProfile, sidecarDirectory);
                        if (peLoader.PlusSearch(metadata.methodDefs.Count(x => x.methodIndex >= 0), metadata.typeDefs.Length, metadata.imageDefs.Length))
                        {
                            il2Cpp = peLoader;
                            flag = true;
                        }
                    }
                    catch {}
                }
                if (!flag)
                {
                    try { flag = il2Cpp.Search(); } catch {}
                }
                if (!flag)
                {
                    try { flag = il2Cpp.SymbolSearch(); } catch {}
                }
                if (!flag)
                {
                    Console.WriteLine("ERROR: Can't use auto mode to process file, try manual mode.");
                    ulong codeRegistration = config.CodeRegistration;
                    ulong metadataRegistration = config.MetadataRegistration;
                    if (codeRegistration == 0 || metadataRegistration == 0)
                    {
                        Console.Write("Input CodeRegistration: ");
                        codeRegistration = Convert.ToUInt64(Console.ReadLine(), 16);
                        Console.Write("Input MetadataRegistration: ");
                        metadataRegistration = Convert.ToUInt64(Console.ReadLine(), 16);
                    }
                    il2Cpp.Init(codeRegistration, metadataRegistration);
                }
                if (il2Cpp.Version >= 27 && il2Cpp.IsDumped)
                {
                    var typeDef = metadata.typeDefs[0];
                    var il2CppType = il2Cpp.types[typeDef.byvalTypeIndex];
                    metadata.ImageBase = il2CppType.data.typeHandle - (il2Cpp.Version < 38 ? metadata.header.typeDefinitionsOffset : metadata.header.typeDefinitions.offset);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                Console.WriteLine("ERROR: An error occurred while processing.");
                return false;
            }
            return true;
        }

        private static void Dump(Metadata metadata, Il2Cpp il2Cpp, string outputDir)
        {
            Console.WriteLine("Dumping...");
            var executor = new Il2CppExecutor(metadata, il2Cpp);
            var decompiler = new Il2CppDecompiler(executor);
            try
            {
                decompiler.Decompile(config, outputDir);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Decompile warning: " + ex.Message);
            }
            Console.WriteLine("Done!");
            if (config.GenerateStruct)
            {
                Console.WriteLine("Generate struct and json scripts...");
                try
                {
                    var scriptGenerator = new StructGenerator(executor);
                    scriptGenerator.WriteScript(outputDir);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Struct warning: " + ex);
                }
                Console.WriteLine("Done!");
            }
            if (config.GenerateDummyDll)
            {
                Console.WriteLine("Generate dummy dll...");
                try
                {
                    DummyAssemblyExporter.Export(executor, outputDir, config.DummyDllAddToken);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("DummyDll warning: " + ex);
                }
                Console.WriteLine("Done!");
            }
        }
    }
}
