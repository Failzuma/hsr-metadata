using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Il2CppDumper
{
    public abstract class Il2Cpp : BinaryStream
    {
        public Il2CppMetadataRegistration pMetadataRegistration;
        private Il2CppCodeRegistration pCodeRegistration;
        public ulong[] methodPointers;
        public ulong[] genericMethodPointers;
        public ulong[] invokerPointers;
        public ulong[] customAttributeGenerators;
        public ulong[] reversePInvokeWrappers;
        public ulong[] unresolvedVirtualCallPointers;
        private ulong[] fieldOffsets;
        public Il2CppType[] types;
        private readonly Dictionary<ulong, Il2CppType> typeDic = new();
        public ulong[] metadataUsages;
        private Il2CppGenericMethodFunctionsDefinitions[] genericMethodTable;
        public ulong[] genericInstPointers;
        public Il2CppGenericInst[] genericInsts;
        public Il2CppMethodSpec[] methodSpecs;
        public Dictionary<int, List<Il2CppMethodSpec>> methodDefinitionMethodSpecs = new();
        public Dictionary<Il2CppMethodSpec, ulong> methodSpecGenericMethodPointers = new();
        private bool fieldOffsetsArePointers;
        protected long metadataUsagesCount;
        public Dictionary<string, Il2CppCodeGenModule> codeGenModules;
        public Dictionary<string, ulong[]> codeGenModuleMethodPointers;
        public Dictionary<string, Dictionary<uint, Il2CppRGCTXDefinition[]>> rgctxsDictionary;
        public Il2CppGenericClass[] genericClasses;
        public bool IsDumped;
        private RuntimeProfile runtimeProfile;
        private string sidecarDirectory;

        public abstract ulong MapVATR(ulong addr);
        public abstract ulong MapRTVA(ulong addr);
        public abstract bool Search();
        public abstract bool PlusSearch(int methodCount, int typeDefinitionsCount, int imageCount);
        public abstract bool SymbolSearch();
        public abstract SectionHelper GetSectionHelper(int methodCount, int typeDefinitionsCount, int imageCount);
        public abstract bool CheckDump();

        protected Il2Cpp(Stream stream) : base(stream) { }

        public void SetProperties(double version, long metadataUsagesCount)
        {
            Version = version;
            this.metadataUsagesCount = metadataUsagesCount;
        }

        public void SetRuntimeProfile(RuntimeProfile profile, string directory)
        {
            runtimeProfile = profile;
            sidecarDirectory = directory;
        }

        protected bool AutoPlusInit(ulong codeRegistration, ulong metadataRegistration)
        {
            if (codeRegistration != 0)
            {
                var limit = this is WebAssemblyMemory ? 0x35000u : 0x50000u; //TODO
                if (Version >= 24.2)
                {
                    pCodeRegistration = MapVATR<Il2CppCodeRegistration>(codeRegistration);
                    if (Version == 31)
                    {
                        if (pCodeRegistration.genericMethodPointersCount > limit)
                        {
                            codeRegistration -= PointerSize * 2;
                        }
                        else
                        {
                            Version = 29;
                            Console.WriteLine($"Change il2cpp version to: {Version}");
                        }
                    }
                    if (Version == 29)
                    {
                        if (pCodeRegistration.genericMethodPointersCount > limit)
                        {
                            Version = 29.1;
                            codeRegistration -= PointerSize * 2;
                            Console.WriteLine($"Change il2cpp version to: {Version}");
                        }
                    }
                    if (Version == 27)
                    {
                        if (pCodeRegistration.reversePInvokeWrapperCount > limit)
                        {
                            Version = 27.1;
                            codeRegistration -= PointerSize;
                            Console.WriteLine($"Change il2cpp version to: {Version}");
                        }
                    }
                    if (Version == 24.4)
                    {
                        codeRegistration -= PointerSize * 2;
                        if (pCodeRegistration.reversePInvokeWrapperCount > limit)
                        {
                            Version = 24.5;
                            codeRegistration -= PointerSize;
                            Console.WriteLine($"Change il2cpp version to: {Version}");
                        }
                    }
                    if (Version == 24.2)
                    {
                        if (pCodeRegistration.interopDataCount == 0) //TODO
                        {
                            Version = 24.3;
                            codeRegistration -= PointerSize * 2;
                            Console.WriteLine($"Change il2cpp version to: {Version}");
                        }
                    }
                }
            }
            Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
            Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
            if (codeRegistration != 0 && metadataRegistration != 0)
            {
                Init(codeRegistration, metadataRegistration);
                return true;
            }
            return false;
        }

        public virtual void Init(ulong codeRegistration, ulong metadataRegistration)
        {
            try { pCodeRegistration = MapVATR<Il2CppCodeRegistration>(codeRegistration); } catch { pCodeRegistration = new Il2CppCodeRegistration(); }
            var limit = this is WebAssemblyMemory ? 0x35000u : 0x50000u; //TODO
            if (Version == 27 && pCodeRegistration.invokerPointersCount > limit)
            {
                Version = 27.1;
                Console.WriteLine($"Change il2cpp version to: {Version}");
                try { pCodeRegistration = MapVATR<Il2CppCodeRegistration>(codeRegistration); } catch { }
            }
            if (Version == 27.1)
            {
                try {
                    var pCodeGenModules = MapVATR<ulong>(pCodeRegistration.codeGenModules, pCodeRegistration.codeGenModulesCount);
                    foreach (var pCodeGenModule in pCodeGenModules)
                    {
                        var codeGenModule = MapVATR<Il2CppCodeGenModule>(pCodeGenModule);
                        if (codeGenModule.rgctxsCount > 0)
                        {
                            var rgctxs = MapVATR<Il2CppRGCTXDefinition>(codeGenModule.rgctxs, codeGenModule.rgctxsCount);
                            if (rgctxs.All(x => x.data.rgctxDataDummy > limit))
                            {
                                Version = 27.2;
                                Console.WriteLine($"Change il2cpp version to: {Version}");
                            }
                            break;
                        }
                    }
                } catch { }
            }
            if (Version == 24.4 && pCodeRegistration.invokerPointersCount > limit)
            {
                Version = 24.5;
                Console.WriteLine($"Change il2cpp version to: {Version}");
                try { pCodeRegistration = MapVATR<Il2CppCodeRegistration>(codeRegistration); } catch { }
            }
            if (Version == 24.2 && pCodeRegistration.codeGenModules == 0) //TODO
            {
                Version = 24.3;
                Console.WriteLine($"Change il2cpp version to: {Version}");
                try { pCodeRegistration = MapVATR<Il2CppCodeRegistration>(codeRegistration); } catch { }
            }
            try { pMetadataRegistration = MapVATR<Il2CppMetadataRegistration>(metadataRegistration); } catch { pMetadataRegistration = new Il2CppMetadataRegistration(); }
            try { genericMethodPointers = MapVATR<ulong>(pCodeRegistration.genericMethodPointers, pCodeRegistration.genericMethodPointersCount); } catch { genericMethodPointers = Array.Empty<ulong>(); }
            try { invokerPointers = MapVATR<ulong>(pCodeRegistration.invokerPointers, pCodeRegistration.invokerPointersCount); } catch { invokerPointers = Array.Empty<ulong>(); }
            if (Version < 27)
            {
                try { customAttributeGenerators = MapVATR<ulong>(pCodeRegistration.customAttributeGenerators, pCodeRegistration.customAttributeCount); } catch { customAttributeGenerators = Array.Empty<ulong>(); }
            }
            if (Version > 16 && Version < 27)
            {
                try { metadataUsages = MapVATR<ulong>(pMetadataRegistration.metadataUsages, metadataUsagesCount); } catch { metadataUsages = Array.Empty<ulong>(); }
            }
            if (Version >= 22)
            {
                if (pCodeRegistration.reversePInvokeWrapperCount != 0)
                    try { reversePInvokeWrappers = MapVATR<ulong>(pCodeRegistration.reversePInvokeWrappers, pCodeRegistration.reversePInvokeWrapperCount); } catch { reversePInvokeWrappers = Array.Empty<ulong>(); }
                if (pCodeRegistration.unresolvedVirtualCallCount != 0)
                    try { unresolvedVirtualCallPointers = MapVATR<ulong>(pCodeRegistration.unresolvedVirtualCallPointers, pCodeRegistration.unresolvedVirtualCallCount); } catch { unresolvedVirtualCallPointers = Array.Empty<ulong>(); }
            }
            try {
                var genericInstsVA = runtimeProfile?.GenericInstsVa ?? pMetadataRegistration.genericInsts;
                var genericInstsCount = runtimeProfile?.GenericInstsCount ?? pMetadataRegistration.genericInstsCount;
                if (runtimeProfile?.GenericInstsAreInline == true)
                {
                    genericInsts = MapVATR<Il2CppGenericInst>(genericInstsVA, genericInstsCount);
                    genericInstPointers = Enumerable.Range(0, checked((int)genericInstsCount))
                        .Select(index => genericInstsVA + (ulong)index * 16)
                        .ToArray();
                }
                else
                {
                    genericInstPointers = MapVATR<ulong>(genericInstsVA, genericInstsCount);
                    genericInsts = Array.ConvertAll(genericInstPointers, MapVATR<Il2CppGenericInst>);
                }
            } catch (Exception error) {
                if (runtimeProfile != null)
                    throw new InvalidDataException("Failed to load the runtime generic-inst table", error);
                genericInstPointers = Array.Empty<ulong>();
                genericInsts = Array.Empty<Il2CppGenericInst>();
            }
            LoadGenericClasses();
            fieldOffsetsArePointers = Version > 21;
            try {
                if (fieldOffsetsArePointers)
                {
                    fieldOffsets = MapVATR<ulong>(pMetadataRegistration.fieldOffsets, pMetadataRegistration.fieldOffsetsCount);
                }
                else
                {
                    fieldOffsets = Array.ConvertAll(MapVATR<uint>(pMetadataRegistration.fieldOffsets, pMetadataRegistration.fieldOffsetsCount), x => (ulong)x);
                }
            } catch {
                fieldOffsets = Array.Empty<ulong>();
            }
            try {
                var typesVA = runtimeProfile?.TypesVa ?? pMetadataRegistration.types;
                var count = runtimeProfile?.TypesCount ?? pMetadataRegistration.typesCount;
                if (typesVA == 0 || count <= 0)
                    throw new InvalidDataException("Type table is unavailable");
                ulong[] typePointers;
                if (runtimeProfile?.TypesAreInline == true)
                {
                    types = MapVATR<Il2CppType>(typesVA, count);
                    typePointers = Enumerable.Range(0, checked((int)count))
                        .Select(index => typesVA + (ulong)index * 16)
                        .ToArray();
                }
                else
                {
                    typePointers = MapVATR<ulong>(typesVA, count);
                    types = Array.ConvertAll(typePointers, MapVATR<Il2CppType>);
                }
                for (var i = 0; i < types.Length; ++i)
                {
                    types[i].Init(Version);
                    typeDic[typePointers[i]] = types[i];
                }
            } catch (Exception error) {
                if (runtimeProfile != null)
                    throw new InvalidDataException("Failed to load the runtime type table", error);
                types = Array.Empty<Il2CppType>();
            }
            try {
                if (runtimeProfile == null || runtimeProfile.MethodPointersVa == 0 || runtimeProfile.MethodPointersCount <= 0)
                    throw new InvalidDataException("Method pointer table is unavailable");
                methodPointers = MapVATR<ulong>(runtimeProfile.MethodPointersVa, runtimeProfile.MethodPointersCount);
            } catch (Exception error) {
                if (runtimeProfile != null)
                    throw new InvalidDataException("Failed to load the runtime method-pointer table", error);
                methodPointers = Array.Empty<ulong>();
            }
            codeGenModules = new Dictionary<string, Il2CppCodeGenModule>(StringComparer.Ordinal);
            codeGenModuleMethodPointers = new Dictionary<string, ulong[]>(StringComparer.Ordinal);
            rgctxsDictionary = new Dictionary<string, Dictionary<uint, Il2CppRGCTXDefinition[]>>(StringComparer.Ordinal);
            methodPointerMap = new Dictionary<int, ulong>();
            fieldOffsetMap = new Dictionary<(int, int), int>();
            try
            {
                var offsetPaths = GetSidecarPaths("field_offsets.bin");
                foreach (var p in offsetPaths)
                {
                    if (File.Exists(p))
                    {
                        var bytes = File.ReadAllBytes(p);
                        for (int i = 0; i + 12 <= bytes.Length; i += 12)
                        {
                            var tidx = BitConverter.ToInt32(bytes, i);
                            var fidx = BitConverter.ToInt32(bytes, i + 4);
                            var off = BitConverter.ToInt32(bytes, i + 8);
                            fieldOffsetMap[(tidx, fidx)] = off;
                        }
                        Console.WriteLine($"Loaded {fieldOffsetMap.Count} field offsets from {p}");
                        break;
                    }
                }
            }
            catch { }
            try
            {
                var mapPaths = GetSidecarPaths("method_mappings.bin");
                foreach (var p in mapPaths)
                {
                    if (File.Exists(p))
                    {
                        var bytes = File.ReadAllBytes(p);
                        for (int i = 0; i + 12 <= bytes.Length; i += 12)
                        {
                            var midx = BitConverter.ToInt32(bytes, i);
                            var ptr = BitConverter.ToUInt64(bytes, i + 4);
                            methodPointerMap[midx] = ptr;
                        }
                        methodPointerMapLoaded = true;
                        Console.WriteLine($"Loaded {methodPointerMap.Count} method mappings from {p}");
                        break;
                    }
                }
            }
            catch { }
            try {
                genericMethodTable = MapVATR<Il2CppGenericMethodFunctionsDefinitions>(pMetadataRegistration.genericMethodTable, pMetadataRegistration.genericMethodTableCount);
                methodSpecs = MapVATR<Il2CppMethodSpec>(pMetadataRegistration.methodSpecs, pMetadataRegistration.methodSpecsCount);
                foreach (var table in genericMethodTable)
                {
                    var methodSpec = methodSpecs[table.genericMethodIndex];
                    var methodDefinitionIndex = methodSpec.methodDefinitionIndex;
                    if (!methodDefinitionMethodSpecs.TryGetValue(methodDefinitionIndex, out var list))
                    {
                        list = new List<Il2CppMethodSpec>();
                        methodDefinitionMethodSpecs.Add(methodDefinitionIndex, list);
                    }
                    list.Add(methodSpec);
                    if (table.indices.methodIndex < genericMethodPointers.Length)
                        methodSpecGenericMethodPointers.Add(methodSpec, genericMethodPointers[table.indices.methodIndex]);
                }
            } catch { }
        }

        private string[] GetSidecarPaths(string fileName)
        {
            return new[] {
                string.IsNullOrEmpty(sidecarDirectory) ? null : Path.Combine(sidecarDirectory, fileName),
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, fileName)
            }.Where(path => !string.IsNullOrEmpty(path)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }

        private void LoadGenericClasses()
        {
            if (runtimeProfile == null)
            {
                try {
                    genericClasses = MapVATR<Il2CppGenericClass>(pMetadataRegistration.genericClasses, pMetadataRegistration.genericClassesCount);
                } catch {
                    genericClasses = Array.Empty<Il2CppGenericClass>();
                }
                return;
            }
            var path = GetSidecarPaths("generic_classes.bin").FirstOrDefault(File.Exists);
            if (path == null)
            {
                throw new FileNotFoundException("generic_classes.bin was not found in the sidecar directory");
            }
            var bytes = File.ReadAllBytes(path);
            var count = Math.Min(runtimeProfile.GenericClassCount, bytes.LongLength / 8);
            if (count != runtimeProfile.GenericClassCount)
                throw new InvalidDataException("generic_classes.bin is shorter than the runtime profile");
            genericClasses = new Il2CppGenericClass[count];
            for (var index = 0; index < count; index++)
            {
                var offset = checked((int)(index * 8));
                var typeDefinitionIndex = BitConverter.ToInt32(bytes, offset);
                var genericInstIndex = BitConverter.ToInt32(bytes, offset + 4);
                var classInst = genericInstIndex >= 0 && genericInstIndex < genericInstPointers.Length
                    ? genericInstPointers[genericInstIndex]
                    : 0;
                genericClasses[index] = new Il2CppGenericClass {
                    typeDefinitionIndex = typeDefinitionIndex,
                    context = new Il2CppGenericContext { class_inst = classInst, method_inst = 0 },
                    cached_class = 0
                };
            }
            Console.WriteLine($"Loaded {genericClasses.Length} generic classes from {path}");
        }

        public T MapVATR<T>(ulong addr) where T : new()
        {
            return ReadClass<T>(MapVATR(addr));
        }

        public T[] MapVATR<T>(ulong addr, ulong count) where T : new()
        {
            return ReadClassArray<T>(MapVATR(addr), count);
        }

        public T[] MapVATR<T>(ulong addr, long count) where T : new()
        {
            return ReadClassArray<T>(MapVATR(addr), count);
        }

        public Dictionary<(int, int), int> fieldOffsetMap = new Dictionary<(int, int), int>();

        public int GetFieldOffsetFromIndex(int typeIndex, int fieldIndexInType, int fieldIndex, bool isValueType, bool isStatic)
        {
            try
            {
                if (fieldOffsetMap.TryGetValue((typeIndex, fieldIndexInType), out var directOffset))
                {
                    return directOffset;
                }
                var offset = -1;
                if (fieldOffsetsArePointers)
                {
                    if (typeIndex >= 0 && typeIndex < fieldOffsets.Length)
                    {
                        var ptr = fieldOffsets[typeIndex];
                        if (ptr > 0)
                        {
                            Position = MapVATR(ptr) + 4ul * (ulong)fieldIndexInType;
                            offset = ReadInt32();
                        }
                    }
                }
                else if (fieldIndex >= 0 && fieldIndex < fieldOffsets.Length)
                {
                    offset = (int)fieldOffsets[fieldIndex];
                }
                if (offset > 0)
                {
                    if (isValueType && !isStatic)
                    {
                        if (Is32Bit)
                        {
                            offset -= 8;
                        }
                        else
                        {
                            offset -= 16;
                        }
                    }
                }
                return offset;
            }
            catch
            {
                return -1;
            }
        }

        public Il2CppType GetIl2CppType(ulong pointer)
        {
            if (!typeDic.TryGetValue(pointer, out var type))
            {
                return null;
            }
            return type;
        }

        public Il2CppType ResolveType(ulong reference)
        {
            if (reference < (ulong)types.Length)
                return types[reference];
            return GetIl2CppType(reference);
        }

        public Il2CppGenericClass GetGenericClass(ulong reference)
        {
            if (reference < (ulong)genericClasses.Length)
                return genericClasses[reference];
            try {
                return MapVATR<Il2CppGenericClass>(reference);
            } catch {
                return null;
            }
        }

        public Il2CppGenericClass GetGenericClass(Il2CppType type)
        {
            return type?.data == null ? null : GetGenericClass(type.data.generic_class);
        }

        public Dictionary<int, ulong> methodPointerMap = new Dictionary<int, ulong>();
        private bool methodPointerMapLoaded;

        public ulong GetMethodPointer(string imageName, Il2CppMethodDefinition methodDef)
        {
            try
            {
                var methodIndex = (int)(methodDef.token & 0x00FFFFFFu) - 1;
                if (methodPointerMapLoaded)
                {
                    return methodPointerMap.TryGetValue(methodIndex, out var ptr) ? ptr : 0;
                }
                if (Version >= 24.2 && codeGenModuleMethodPointers.TryGetValue(imageName, out var ptrs))
                {
                    var methodToken = methodDef.token;
                    var methodPointerIndex = methodToken & 0x00FFFFFFu;
                    if (methodPointerIndex > 0 && methodPointerIndex - 1 < (uint)ptrs.Length)
                        return ptrs[methodPointerIndex - 1];
                }
                if (methodPointers != null && methodIndex >= 0 && methodIndex < methodPointers.Length)
                {
                    return methodPointers[methodIndex];
                }
            }
            catch { }
            return 0;
        }

        public virtual ulong GetRVA(ulong pointer)
        {
            return pointer;
        }
    }
}
