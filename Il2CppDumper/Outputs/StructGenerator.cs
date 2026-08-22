using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using static Il2CppDumper.Il2CppConstants;

namespace Il2CppDumper
{
    public class StructGenerator
    {
        private readonly Il2CppExecutor executor;
        private readonly Metadata metadata;
        private readonly Il2Cpp il2Cpp;
        private readonly Dictionary<Il2CppTypeDefinition, string> typeDefImageNames = new();
        private readonly HashSet<string> structNameHashSet = new(StringComparer.Ordinal);
        private readonly List<StructInfo> structInfoList = new();
        private readonly Dictionary<string, StructInfo> structInfoWithStructName = new();
        private readonly HashSet<StructInfo> structCache = new();
        private readonly Dictionary<Il2CppTypeDefinition, string> structNameDic = new();
        private readonly Dictionary<ulong, string> genericClassStructNameDic = new();
        private readonly Dictionary<string, Il2CppType> nameGenericClassDic = new();
        private readonly List<ulong> genericClassList = new();
        private readonly StringBuilder arrayClassHeader = new();
        private readonly StringBuilder methodInfoHeader = new();
        private readonly StringBuilder methodDeclarationsHeader = new();
        private static readonly HashSet<ulong> methodInfoCache = new();
        private static readonly HashSet<string> keyword = new(StringComparer.Ordinal)
        { "klass", "monitor", "register", "_cs", "auto", "friend", "template", "flat", "default", "_ds", "interrupt",
            "unsigned", "signed", "asm", "if", "case", "break", "continue", "do", "new", "_", "short", "union", "class", "namespace"};
        private static readonly HashSet<string> specialKeywords = new(StringComparer.Ordinal)
        { "inline", "near", "far" };

        public StructGenerator(Il2CppExecutor il2CppExecutor)
        {
            executor = il2CppExecutor;
            metadata = il2CppExecutor.metadata;
            il2Cpp = il2CppExecutor.il2Cpp;
        }

        public void WriteScript(string outputDir)
        {
            try
            {
                var json = new ScriptJson();
            // 生成唯一名称
            for (var imageIndex = 0; imageIndex < metadata.imageDefs.Length; imageIndex++)
            {
                var imageDef = metadata.imageDefs[imageIndex];
                var imageName = metadata.GetStringFromIndex(imageDef.nameIndex);
                var typeEnd = imageDef.typeStart + imageDef.typeCount;
                for (int typeIndex = imageDef.typeStart; typeIndex < typeEnd; typeIndex++)
                {
                    if (typeIndex >= 0 && typeIndex < metadata.typeDefs.Length)
                    {
                        var typeDef = metadata.typeDefs[typeIndex];
                        typeDefImageNames[typeDef] = imageName;
                        CreateStructNameDic(typeDef);
                    }
                }
            }
            // 生成后面处理泛型实例要用到的字典
            foreach (var il2CppType in il2Cpp.types.Where(x => x.type == Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST))
            {
                try
                {
                    if (il2CppType.data == null)
                        continue;
                    Il2CppGenericClass genericClass = null;
                    try
                    {
                        genericClass = il2Cpp.GetGenericClass(il2CppType);
                    }
                    catch { }
                    var typeDef = executor.GetGenericClassTypeDefinition(genericClass);
                    if (typeDef == null)
                    {
                        var idx = (int)il2CppType.datapoint;
                        if (idx >= 0 && idx < metadata.typeDefs.Length)
                            typeDef = metadata.typeDefs[idx];
                    }
                    if (typeDef == null)
                    {
                        continue;
                    }
                    if (!structNameDic.TryGetValue(typeDef, out var typeBaseName))
                    {
                        typeBaseName = FixName(executor.GetTypeDefName(typeDef, true, true));
                        structNameDic[typeDef] = typeBaseName;
                    }
                    var typeToReplaceName = FixName(executor.GetTypeDefName(typeDef, true, true));
                    var typeReplaceName = FixName(executor.GetTypeName(il2CppType, true, false));
                    var typeStructName = typeBaseName.Replace(typeToReplaceName, typeReplaceName);
                    nameGenericClassDic[typeStructName] = il2CppType;
                    genericClassStructNameDic[il2CppType.data.generic_class] = typeStructName;
                }
                catch { }
            }
            // 处理函数
            foreach (var imageDef in metadata.imageDefs)
            {
                var imageName = metadata.GetStringFromIndex(imageDef.nameIndex);
                var typeEnd = imageDef.typeStart + imageDef.typeCount;
                for (int typeIndex = imageDef.typeStart; typeIndex < typeEnd; typeIndex++)
                {
                    if (typeIndex < 0 || typeIndex >= metadata.typeDefs.Length)
                        continue;
                    var typeDef = metadata.typeDefs[typeIndex];
                    AddStruct(typeDef);
                    var typeName = executor.GetTypeDefName(typeDef, true, true);
                    var methodEnd = typeDef.methodStart + typeDef.method_count;
                    for (var i = typeDef.methodStart; i < methodEnd; ++i)
                    {
                        if (i < 0 || i >= metadata.methodDefs.Length)
                            continue;
                        try
                        {
                            var methodDef = metadata.methodDefs[i];
                            var methodName = metadata.GetStringFromIndex(methodDef.nameIndex);
                            var methodPointer = il2Cpp.GetMethodPointer(imageName, methodDef);
                            if (methodPointer > 0)
                            {
                                var methodTypeSignature = new List<Il2CppTypeEnum>();
                                var scriptMethod = new ScriptMethod();
                                json.ScriptMethod.Add(scriptMethod);
                                scriptMethod.Address = il2Cpp.GetRVA(methodPointer);
                                var methodFullName = typeName + "$$" + methodName;
                                scriptMethod.Name = methodFullName;

                                var methodReturnType = (methodDef.returnType >= 0 && methodDef.returnType < il2Cpp.types.Length) ? il2Cpp.types[methodDef.returnType] : null;
                                var returnType = methodReturnType != null ? ParseType(methodReturnType) : "void";
                                if (methodReturnType != null && methodReturnType.byref == 1)
                                {
                                    returnType += "*";
                                }
                                methodTypeSignature.Add((methodReturnType != null && methodReturnType.byref == 1) ? Il2CppTypeEnum.IL2CPP_TYPE_PTR : (methodReturnType?.type ?? Il2CppTypeEnum.IL2CPP_TYPE_VOID));
                                var signature = $"{returnType} {FixName(methodFullName)} (";
                                var parameterStrs = new List<string>();
                                if ((methodDef.flags & METHOD_ATTRIBUTE_STATIC) == 0)
                                {
                                    var thisType = (typeDef.byvalTypeIndex >= 0 && typeDef.byvalTypeIndex < il2Cpp.types.Length) ? ParseType(il2Cpp.types[typeDef.byvalTypeIndex]) : "void*";
                                    methodTypeSignature.Add((typeDef.byvalTypeIndex >= 0 && typeDef.byvalTypeIndex < il2Cpp.types.Length) ? il2Cpp.types[typeDef.byvalTypeIndex].type : Il2CppTypeEnum.IL2CPP_TYPE_PTR);
                                    parameterStrs.Add($"{thisType} __this");
                                }
                                else if (il2Cpp.Version <= 24)
                                {
                                    methodTypeSignature.Add(Il2CppTypeEnum.IL2CPP_TYPE_PTR);
                                    parameterStrs.Add($"Il2CppObject* __this");
                                }
                                for (var j = 0; j < methodDef.parameterCount; j++)
                                {
                                    if (methodDef.parameterStart + j < 0 || methodDef.parameterStart + j >= metadata.parameterDefs.Length)
                                        continue;
                                    var parameterDef = metadata.parameterDefs[methodDef.parameterStart + j];
                                    var parameterName = metadata.GetStringFromIndex(parameterDef.nameIndex);
                                    var parameterType = (parameterDef.typeIndex >= 0 && parameterDef.typeIndex < il2Cpp.types.Length) ? il2Cpp.types[parameterDef.typeIndex] : null;
                                    var parameterCType = parameterType != null ? ParseType(parameterType) : "void*";
                                    if (parameterType != null && parameterType.byref == 1)
                                    {
                                        parameterCType += "*";
                                    }
                                    methodTypeSignature.Add((parameterType != null && parameterType.byref == 1) ? Il2CppTypeEnum.IL2CPP_TYPE_PTR : (parameterType?.type ?? Il2CppTypeEnum.IL2CPP_TYPE_VOID));
                                    parameterStrs.Add($"{parameterCType} {FixName(parameterName)}");
                                }
                                methodTypeSignature.Add(Il2CppTypeEnum.IL2CPP_TYPE_PTR);
                                parameterStrs.Add("const MethodInfo* method");
                                signature += string.Join(", ", parameterStrs);
                                signature += ");";
                                scriptMethod.Signature = signature;
                                scriptMethod.TypeSignature = GetMethodTypeSignature(methodTypeSignature);
                                methodDeclarationsHeader.AppendLine(signature);
                            }
                            //泛型实例函数
                            if (il2Cpp.methodDefinitionMethodSpecs != null && il2Cpp.methodDefinitionMethodSpecs.TryGetValue(i, out var methodSpecs))
                            {
                                foreach (var methodSpec in methodSpecs)
                                {
                                    if (il2Cpp.methodSpecGenericMethodPointers != null && il2Cpp.methodSpecGenericMethodPointers.TryGetValue(methodSpec, out var genericMethodPointer) && genericMethodPointer > 0)
                                    {
                                        var methodTypeSignature = new List<Il2CppTypeEnum>();
                                        var scriptMethod = new ScriptMethod();
                                        json.ScriptMethod.Add(scriptMethod);
                                        scriptMethod.Address = il2Cpp.GetRVA(genericMethodPointer);
                                        var methodInfoName = $"MethodInfo_{scriptMethod.Address:X}";
                                        var structTypeName = structNameDic.TryGetValue(typeDef, out var sn) ? sn : FixName(typeName);
                                        var rgctxs = GenerateRGCTX(imageName, methodDef);
                                        if (methodInfoCache.Add(genericMethodPointer))
                                        {
                                            GenerateMethodInfo(methodInfoName, structTypeName, rgctxs);
                                        }
                                        (var methodSpecTypeName, var methodSpecMethodName) = executor.GetMethodSpecName(methodSpec, true);
                                        var methodFullName = methodSpecTypeName + "$$" + methodSpecMethodName;
                                        scriptMethod.Name = methodFullName;

                                        var genericContext = executor.GetMethodSpecGenericContext(methodSpec);
                                        var methodReturnType = (methodDef.returnType >= 0 && methodDef.returnType < il2Cpp.types.Length) ? il2Cpp.types[methodDef.returnType] : null;
                                        var returnType = methodReturnType != null ? ParseType(methodReturnType, genericContext) : "void";
                                        if (methodReturnType != null && methodReturnType.byref == 1)
                                        {
                                            returnType += "*";
                                        }
                                        methodTypeSignature.Add((methodReturnType != null && methodReturnType.byref == 1) ? Il2CppTypeEnum.IL2CPP_TYPE_PTR : (methodReturnType?.type ?? Il2CppTypeEnum.IL2CPP_TYPE_VOID));
                                        var signature = $"{returnType} {FixName(methodFullName)} (";
                                        var parameterStrs = new List<string>();
                                        if ((methodDef.flags & METHOD_ATTRIBUTE_STATIC) == 0)
                                        {
                                            string thisType;
                                            if (methodSpec.classIndexIndex != -1)
                                            {
                                                var typeBaseName = structNameDic.TryGetValue(typeDef, out var sbn) ? sbn : FixName(typeName);
                                                var typeToReplaceName = FixName(typeName);
                                                var typeReplaceName = FixName(methodSpecTypeName);
                                                var typeStructName = typeBaseName.Replace(typeToReplaceName, typeReplaceName);
                                                if (nameGenericClassDic.TryGetValue(typeStructName, out var il2CppType))
                                                {
                                                    thisType = ParseType(il2CppType);
                                                    methodTypeSignature.Add(il2CppType.type);
                                                }
                                                else
                                                {
                                                    thisType = (typeDef.byvalTypeIndex >= 0 && typeDef.byvalTypeIndex < il2Cpp.types.Length) ? ParseType(il2Cpp.types[typeDef.byvalTypeIndex]) : "void*";
                                                    methodTypeSignature.Add((typeDef.byvalTypeIndex >= 0 && typeDef.byvalTypeIndex < il2Cpp.types.Length) ? il2Cpp.types[typeDef.byvalTypeIndex].type : Il2CppTypeEnum.IL2CPP_TYPE_PTR);
                                                }
                                            }
                                            else
                                            {
                                                thisType = (typeDef.byvalTypeIndex >= 0 && typeDef.byvalTypeIndex < il2Cpp.types.Length) ? ParseType(il2Cpp.types[typeDef.byvalTypeIndex]) : "void*";
                                                methodTypeSignature.Add((typeDef.byvalTypeIndex >= 0 && typeDef.byvalTypeIndex < il2Cpp.types.Length) ? il2Cpp.types[typeDef.byvalTypeIndex].type : Il2CppTypeEnum.IL2CPP_TYPE_PTR);
                                            }
                                            parameterStrs.Add($"{thisType} __this");
                                        }
                                        else if (il2Cpp.Version <= 24)
                                        {
                                            methodTypeSignature.Add(Il2CppTypeEnum.IL2CPP_TYPE_PTR);
                                            parameterStrs.Add($"Il2CppObject* __this");
                                        }
                                        for (var j = 0; j < methodDef.parameterCount; j++)
                                        {
                                            if (methodDef.parameterStart + j < 0 || methodDef.parameterStart + j >= metadata.parameterDefs.Length)
                                                continue;
                                            var parameterDef = metadata.parameterDefs[methodDef.parameterStart + j];
                                            var parameterName = metadata.GetStringFromIndex(parameterDef.nameIndex);
                                            var parameterType = (parameterDef.typeIndex >= 0 && parameterDef.typeIndex < il2Cpp.types.Length) ? il2Cpp.types[parameterDef.typeIndex] : null;
                                            var parameterCType = parameterType != null ? ParseType(parameterType, genericContext) : "void*";
                                            if (parameterType != null && parameterType.byref == 1)
                                            {
                                                parameterCType += "*";
                                            }
                                            methodTypeSignature.Add((parameterType != null && parameterType.byref == 1) ? Il2CppTypeEnum.IL2CPP_TYPE_PTR : (parameterType?.type ?? Il2CppTypeEnum.IL2CPP_TYPE_VOID));
                                            parameterStrs.Add($"{parameterCType} {FixName(parameterName)}");
                                        }
                                        methodTypeSignature.Add(Il2CppTypeEnum.IL2CPP_TYPE_PTR);
                                        parameterStrs.Add($"const {methodInfoName}* method");
                                        signature += string.Join(", ", parameterStrs);
                                        signature += ");";
                                        scriptMethod.Signature = signature;
                                        scriptMethod.TypeSignature = GetMethodTypeSignature(methodTypeSignature);
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            //处理函数范围
            List<ulong> orderedPointers = new List<ulong>();
            if (il2Cpp.methodPointers != null)
            {
                orderedPointers.AddRange(il2Cpp.methodPointers);
            }
            foreach (var pair in il2Cpp.codeGenModuleMethodPointers)
            {
                orderedPointers.AddRange(pair.Value);
            }
            orderedPointers.AddRange(il2Cpp.genericMethodPointers);
            orderedPointers.AddRange(il2Cpp.invokerPointers);
            if (il2Cpp.Version < 29)
            {
                orderedPointers.AddRange(executor.customAttributeGenerators);
            }
            if (il2Cpp.Version >= 22)
            {
                if (il2Cpp.reversePInvokeWrappers != null)
                    orderedPointers.AddRange(il2Cpp.reversePInvokeWrappers);
                if (il2Cpp.unresolvedVirtualCallPointers != null)
                    orderedPointers.AddRange(il2Cpp.unresolvedVirtualCallPointers);
            }
            //TODO interopData内也包含函数
            orderedPointers = orderedPointers.Distinct().OrderBy(x => x).ToList();
            orderedPointers.Remove(0);
            json.Addresses = new ulong[orderedPointers.Count];
            for (int i = 0; i < orderedPointers.Count; i++)
            {
                json.Addresses[i] = il2Cpp.GetRVA(orderedPointers[i]);
            }
            // 处理MetadataUsage
            if (il2Cpp.Version >= 27)
            {
                var sectionHelper = executor.GetSectionHelper();
                foreach (var sec in sectionHelper.Data)
                {
                    il2Cpp.Position = sec.offset;
                    var end = Math.Min(sec.offsetEnd, il2Cpp.Length) - il2Cpp.PointerSize;
                    while (il2Cpp.Position < end)
                    {
                        var addr = il2Cpp.Position;
                        var metadataValue = il2Cpp.ReadUIntPtr();
                        var position = il2Cpp.Position;
                        if (metadataValue < uint.MaxValue)
                        {
                            var encodedToken = (uint)metadataValue;
                            var usage = Metadata.GetEncodedIndexType(encodedToken);
                            if (usage > 0 && usage <= 6)
                            {
                                var decodedIndex = metadata.GetDecodedMethodIndex(encodedToken);
                                if (metadataValue == ((usage << 29) | (decodedIndex << 1)) + 1)
                                {
                                    var va = il2Cpp.MapRTVA(addr);
                                    if (va > 0)
                                    {
                                        switch ((Il2CppMetadataUsage)usage)
                                        {
                                            case Il2CppMetadataUsage.kIl2CppMetadataUsageInvalid:
                                                break;
                                            case Il2CppMetadataUsage.kIl2CppMetadataUsageTypeInfo:
                                                if (decodedIndex < il2Cpp.types.Length)
                                                {
                                                    AddMetadataUsageTypeInfo(json, decodedIndex, va);
                                                }
                                                break;
                                            case Il2CppMetadataUsage.kIl2CppMetadataUsageIl2CppType:
                                                if (decodedIndex < il2Cpp.types.Length)
                                                {
                                                    AddMetadataUsageIl2CppType(json, decodedIndex, va);
                                                }
                                                break;
                                            case Il2CppMetadataUsage.kIl2CppMetadataUsageMethodDef:
                                                if (decodedIndex < metadata.methodDefs.Length)
                                                {
                                                    AddMetadataUsageMethodDef(json, decodedIndex, va);
                                                }
                                                break;
                                            case Il2CppMetadataUsage.kIl2CppMetadataUsageFieldInfo:
                                                if (decodedIndex < metadata.fieldRefs.Length)
                                                {
                                                    AddMetadataUsageFieldInfo(json, decodedIndex, va);
                                                }
                                                break;
                                            case Il2CppMetadataUsage.kIl2CppMetadataUsageStringLiteral:
                                                if (decodedIndex < metadata.stringLiterals.Length)
                                                {
                                                    AddMetadataUsageStringLiteral(json, decodedIndex, va);
                                                }
                                                break;
                                            case Il2CppMetadataUsage.kIl2CppMetadataUsageMethodRef:
                                                if (decodedIndex < il2Cpp.methodSpecs.Length)
                                                {
                                                    AddMetadataUsageMethodRef(json, decodedIndex, va);
                                                }
                                                break;
                                        }
                                        if (il2Cpp.Position != position)
                                        {
                                            il2Cpp.Position = position;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else if (il2Cpp.Version > 16 && il2Cpp.Version < 27 && il2Cpp.metadataUsages != null && il2Cpp.metadataUsages.Length > 0)
            {
                foreach (var i in metadata.metadataUsageDic[Il2CppMetadataUsage.kIl2CppMetadataUsageTypeInfo])
                {
                    if (i.Key < (uint)il2Cpp.metadataUsages.Length)
                        AddMetadataUsageTypeInfo(json, i.Value, il2Cpp.metadataUsages[i.Key]);
                }
                foreach (var i in metadata.metadataUsageDic[Il2CppMetadataUsage.kIl2CppMetadataUsageIl2CppType])
                {
                    if (i.Key < (uint)il2Cpp.metadataUsages.Length)
                        AddMetadataUsageIl2CppType(json, i.Value, il2Cpp.metadataUsages[i.Key]);
                }
                foreach (var i in metadata.metadataUsageDic[Il2CppMetadataUsage.kIl2CppMetadataUsageMethodDef])
                {
                    if (i.Key < (uint)il2Cpp.metadataUsages.Length)
                        AddMetadataUsageMethodDef(json, i.Value, il2Cpp.metadataUsages[i.Key]);
                }
                foreach (var i in metadata.metadataUsageDic[Il2CppMetadataUsage.kIl2CppMetadataUsageFieldInfo])
                {
                    if (i.Key < (uint)il2Cpp.metadataUsages.Length)
                        AddMetadataUsageFieldInfo(json, i.Value, il2Cpp.metadataUsages[i.Key]);
                }
                foreach (var i in metadata.metadataUsageDic[Il2CppMetadataUsage.kIl2CppMetadataUsageStringLiteral])
                {
                    if (i.Key < (uint)il2Cpp.metadataUsages.Length)
                        AddMetadataUsageStringLiteral(json, i.Value, il2Cpp.metadataUsages[i.Key]);
                }
                foreach (var i in metadata.metadataUsageDic[Il2CppMetadataUsage.kIl2CppMetadataUsageMethodRef])
                {
                    if (i.Key < (uint)il2Cpp.metadataUsages.Length)
                        AddMetadataUsageMethodRef(json, i.Value, il2Cpp.metadataUsages[i.Key]);
                }
            }
            //输出单独的StringLiteral
            object stringLiterals;
            if (json.ScriptString.Count > 0)
            {
                stringLiterals = json.ScriptString.Select(x => new
                {
                    value = x.Value,
                    address = $"0x{x.Address:X}"
                }).ToArray();
            }
            else if (metadata.stringLiterals != null && metadata.stringLiterals.Length > 0)
            {
                var list = new List<object>(metadata.stringLiterals.Length);
                for (int i = 0; i < metadata.stringLiterals.Length; i++)
                {
                    try
                    {
                        var str = metadata.GetStringLiteralFromIndex((uint)i);
                        if (!string.IsNullOrEmpty(str))
                        {
                            list.Add(new
                            {
                                value = str,
                                address = $"0x{i:X}"
                            });
                        }
                    }
                    catch { }
                }
                stringLiterals = list.ToArray();
            }
            else
            {
                stringLiterals = Array.Empty<object>();
            }
            var jsonOptions = new JsonSerializerOptions() { WriteIndented = true, IncludeFields = true };
            File.WriteAllText(outputDir + "stringliteral.json", JsonSerializer.Serialize(stringLiterals, jsonOptions), new UTF8Encoding(false));
            //写入文件
            File.WriteAllText(outputDir + "script.json", JsonSerializer.Serialize(json, jsonOptions));
            //il2cpp.h
            for (int i = 0; i < genericClassList.Count; i++)
            {
                var pointer = genericClassList[i];
                AddGenericClassStruct(pointer);
            }
            var headerStruct = new StringBuilder();
            foreach (var info in structInfoList)
            {
                structInfoWithStructName[info.TypeName + "_o"] = info;
            }
            foreach (var info in structInfoList)
            {
                headerStruct.Append(RecursionStructInfo(info));
            }
            var sb = new StringBuilder();
            sb.Append(HeaderConstants.GenericHeader);
            switch (il2Cpp.Version)
            {
                case 22:
                    sb.Append(HeaderConstants.HeaderV22);
                    break;
                case 23:
                case 24:
                    sb.Append(HeaderConstants.HeaderV240);
                    break;
                case 24.1:
                    sb.Append(HeaderConstants.HeaderV241);
                    break;
                case 24.2:
                case 24.3:
                case 24.4:
                case 24.5:
                    sb.Append(HeaderConstants.HeaderV242);
                    break;
                case 27:
                case 27.1:
                case 27.2:
                    sb.Append(HeaderConstants.HeaderV27);
                    break;
                case 29:
                case 29.1:
                case 31:
                case 35:
                case 38:
                case 39:
                    sb.Append(HeaderConstants.HeaderV29);
                    break;
                default:
                    Console.WriteLine($"WARNING: This il2cpp version [{il2Cpp.Version}] does not support generating .h files");
                    return;
            }
            sb.Append(headerStruct);
            sb.Append(arrayClassHeader);
            sb.Append(methodInfoHeader);
            sb.Append("\n// Method Declarations\n");
            sb.Append(methodDeclarationsHeader);
            File.WriteAllText(outputDir + "il2cpp.h", sb.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine("WriteScript inner exception: " + ex);
                throw;
            }
        }

        private void AddMetadataUsageTypeInfo(ScriptJson json, uint index, ulong address)
        {
            var type = il2Cpp.types[index];
            var typeName = executor.GetTypeName(type, true, false);
            var scriptMetadata = new ScriptMetadata();
            json.ScriptMetadata.Add(scriptMetadata);
            scriptMetadata.Address = il2Cpp.GetRVA(address);
            scriptMetadata.Name = typeName + "_TypeInfo";
            var signature = GetIl2CppStructName(type);
            if (signature.EndsWith("_array"))
            {
                scriptMetadata.Signature = "Il2CppClass*";
            }
            else
            {
                scriptMetadata.Signature = FixName(signature) + "_c*";
            }
        }

        private void AddMetadataUsageIl2CppType(ScriptJson json, uint index, ulong address)
        {
            var type = il2Cpp.types[index];
            var typeName = executor.GetTypeName(type, true, false);
            var scriptMetadata = new ScriptMetadata();
            json.ScriptMetadata.Add(scriptMetadata);
            scriptMetadata.Address = il2Cpp.GetRVA(address);
            scriptMetadata.Name = typeName + "_var";
            scriptMetadata.Signature = "Il2CppType*";
        }

        private void AddMetadataUsageMethodDef(ScriptJson json, uint index, ulong address)
        {
            var methodDef = metadata.methodDefs[index];
            var typeDef = metadata.typeDefs[methodDef.declaringType];
            var typeName = executor.GetTypeDefName(typeDef, true, true);
            var methodName = typeName + "." + metadata.GetStringFromIndex(methodDef.nameIndex) + "()";
            var scriptMetadataMethod = new ScriptMetadataMethod();
            json.ScriptMetadataMethod.Add(scriptMetadataMethod);
            scriptMetadataMethod.Address = il2Cpp.GetRVA(address);
            scriptMetadataMethod.Name = "Method$" + methodName;
            var imageName = typeDefImageNames[typeDef];
            var methodPointer = il2Cpp.GetMethodPointer(imageName, methodDef);
            if (methodPointer > 0)
            {
                scriptMetadataMethod.MethodAddress = il2Cpp.GetRVA(methodPointer);
            }
        }

        private void AddMetadataUsageFieldInfo(ScriptJson json, uint index, ulong address)
        {
            var fieldRef = metadata.fieldRefs[index];
            var type = il2Cpp.types[fieldRef.typeIndex];
            var typeDef = GetTypeDefinition(type);
            var fieldDef = metadata.fieldDefs[typeDef.fieldStart + fieldRef.fieldIndex];
            var fieldName = executor.GetTypeName(type, true, false) + "." + metadata.GetStringFromIndex(fieldDef.nameIndex);
            var scriptMetadata = new ScriptMetadata();
            json.ScriptMetadata.Add(scriptMetadata);
            scriptMetadata.Address = il2Cpp.GetRVA(address);
            scriptMetadata.Name = "Field$" + fieldName;
        }

        private void AddMetadataUsageStringLiteral(ScriptJson json, uint index, ulong address)
        {
            var scriptString = new ScriptString();
            json.ScriptString.Add(scriptString);
            scriptString.Address = il2Cpp.GetRVA(address);
            scriptString.Value = metadata.GetStringLiteralFromIndex(index);
        }

        private void AddMetadataUsageMethodRef(ScriptJson json, uint index, ulong address)
        {
            var methodSpec = il2Cpp.methodSpecs[index];
            var scriptMetadataMethod = new ScriptMetadataMethod();
            json.ScriptMetadataMethod.Add(scriptMetadataMethod);
            scriptMetadataMethod.Address = il2Cpp.GetRVA(address);
            (var methodSpecTypeName, var methodSpecMethodName) = executor.GetMethodSpecName(methodSpec, true);
            scriptMetadataMethod.Name = "Method$" + methodSpecTypeName + "." + methodSpecMethodName + "()";
            if (il2Cpp.methodSpecGenericMethodPointers.ContainsKey(methodSpec))
            {
                var genericMethodPointer = il2Cpp.methodSpecGenericMethodPointers[methodSpec];
                if (genericMethodPointer > 0)
                {
                    scriptMetadataMethod.MethodAddress = il2Cpp.GetRVA(genericMethodPointer);
                }
            }
        }

        private static string FixName(string str)
        {
            if (keyword.Contains(str))
            {
                str = "_" + str;
            }
            else if (specialKeywords.Contains(str))
            {
                str = "_" + str + "_";
            }

            if (Regex.IsMatch(str, "^[0-9]"))
            {
                return "_" + str;
            }
            else
            {
                return Regex.Replace(str, "[^a-zA-Z0-9_]", "_");
            }
        }

        private string ParseType(Il2CppType il2CppType, Il2CppGenericContext context = null)
        {
            switch (il2CppType.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_VOID:
                    return "void";
                case Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN:
                    return "bool";
                case Il2CppTypeEnum.IL2CPP_TYPE_CHAR:
                    return "uint16_t"; //Il2CppChar
                case Il2CppTypeEnum.IL2CPP_TYPE_I1:
                    return "int8_t";
                case Il2CppTypeEnum.IL2CPP_TYPE_U1:
                    return "uint8_t";
                case Il2CppTypeEnum.IL2CPP_TYPE_I2:
                    return "int16_t";
                case Il2CppTypeEnum.IL2CPP_TYPE_U2:
                    return "uint16_t";
                case Il2CppTypeEnum.IL2CPP_TYPE_I4:
                    return "int32_t";
                case Il2CppTypeEnum.IL2CPP_TYPE_U4:
                    return "uint32_t";
                case Il2CppTypeEnum.IL2CPP_TYPE_I8:
                    return "int64_t";
                case Il2CppTypeEnum.IL2CPP_TYPE_U8:
                    return "uint64_t";
                case Il2CppTypeEnum.IL2CPP_TYPE_R4:
                    return "float";
                case Il2CppTypeEnum.IL2CPP_TYPE_R8:
                    return "double";
                case Il2CppTypeEnum.IL2CPP_TYPE_STRING:
                    return "System_String_o*";
                case Il2CppTypeEnum.IL2CPP_TYPE_PTR:
                    {
                        var oriType = il2Cpp.ResolveType(il2CppType.data.type);
                        return ParseType(oriType) + "*";
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                    {
                        var typeDef = executor.GetTypeDefinitionFromIl2CppType(il2CppType);
                        if (typeDef != null && typeDef.IsEnum)
                        {
                            var elemIdx = typeDef.GetEnumElementTypeIndex(il2Cpp.Version);
                            if (elemIdx >= 0 && elemIdx < il2Cpp.types.Length)
                                return ParseType(il2Cpp.types[elemIdx]);
                            return "int32_t";
                        }
                        return (typeDef != null && structNameDic.TryGetValue(typeDef, out var sn) ? sn : "ValueType") + "_o";
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_CLASS:
                    {
                        var typeDef = executor.GetTypeDefinitionFromIl2CppType(il2CppType);
                        return (typeDef != null && structNameDic.TryGetValue(typeDef, out var sn) ? sn : "Object") + "_o*";
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_VAR:
                    {
                        if (context != null)
                        {
                            var genericParameter = executor.GetGenericParameteFromIl2CppType(il2CppType);
                            var genericInst = il2Cpp.MapVATR<Il2CppGenericInst>(context.class_inst);
                            var pointers = il2Cpp.MapVATR<ulong>(genericInst.type_argv, genericInst.type_argc);
                            var pointer = pointers[genericParameter.num];
                            var type = il2Cpp.GetIl2CppType(pointer);
                            return ParseType(type);
                        }
                        return "Il2CppObject*";
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_ARRAY:
                    {
                        var arrayType = il2Cpp.MapVATR<Il2CppArrayType>(il2CppType.data.array);
                        var elementType = il2Cpp.GetIl2CppType(arrayType.etype);
                        var elementStructName = GetIl2CppStructName(elementType, context);
                        var typeStructName = elementStructName + "_array";
                        if (structNameHashSet.Add(typeStructName))
                        {
                            ParseArrayClassStruct(elementType, context);
                        }
                        return typeStructName + "*";
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                    {
                        var genericClass = il2Cpp.GetGenericClass(il2CppType);
                        var typeDef = executor.GetGenericClassTypeDefinition(genericClass);
                        if (!genericClassStructNameDic.TryGetValue(il2CppType.data.generic_class, out var typeStructName))
                        {
                            typeStructName = "GenericInst_" + il2CppType.datapoint;
                        }
                        if (structNameHashSet.Add(typeStructName))
                        {
                            genericClassList.Add(il2CppType.data.generic_class);
                        }
                        if (typeDef != null && typeDef.IsValueType)
                        {
                            if (typeDef.IsEnum)
                            {
                                var elemIdx = typeDef.GetEnumElementTypeIndex(il2Cpp.Version);
                                if (elemIdx >= 0 && elemIdx < il2Cpp.types.Length)
                                    return ParseType(il2Cpp.types[elemIdx]);
                                return "int32_t";
                            }
                            return typeStructName + "_o";
                        }
                        return typeStructName + "_o*";
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_TYPEDBYREF:
                    return "Il2CppObject*";
                case Il2CppTypeEnum.IL2CPP_TYPE_I:
                    return "intptr_t";
                case Il2CppTypeEnum.IL2CPP_TYPE_U:
                    return "uintptr_t";
                case Il2CppTypeEnum.IL2CPP_TYPE_OBJECT:
                    return "Il2CppObject*";
                case Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
                    {
                        var elementType = il2Cpp.ResolveType(il2CppType.data.type);
                        var elementStructName = GetIl2CppStructName(elementType, context);
                        var typeStructName = elementStructName + "_array";
                        if (structNameHashSet.Add(typeStructName))
                        {
                            ParseArrayClassStruct(elementType, context);
                        }
                        return typeStructName + "*";
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_MVAR:
                    {
                        if (context != null)
                        {
                            var genericParameter = executor.GetGenericParameteFromIl2CppType(il2CppType);
                            //https://github.com/Perfare/Il2CppDumper/issues/687
                            if (context.method_inst == 0 && context.class_inst != 0)
                            {
                                goto case Il2CppTypeEnum.IL2CPP_TYPE_VAR;
                            }
                            var genericInst = il2Cpp.MapVATR<Il2CppGenericInst>(context.method_inst);
                            var pointers = il2Cpp.MapVATR<ulong>(genericInst.type_argv, genericInst.type_argc);
                            var pointer = pointers[genericParameter.num];
                            var type = il2Cpp.GetIl2CppType(pointer);
                            return ParseType(type);
                        }
                        return "Il2CppObject*";
                    }
                default:
                    throw new NotSupportedException();
            }
        }
        public static string GetMethodTypeSignature(List<Il2CppTypeEnum> types)
        {
            string signature = string.Empty;
            foreach (Il2CppTypeEnum type in types)
            {
                signature += type switch
                {
                    Il2CppTypeEnum.IL2CPP_TYPE_VOID => "v",
                    Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN or Il2CppTypeEnum.IL2CPP_TYPE_CHAR or Il2CppTypeEnum.IL2CPP_TYPE_I1 or Il2CppTypeEnum.IL2CPP_TYPE_U1 or Il2CppTypeEnum.IL2CPP_TYPE_I2 or Il2CppTypeEnum.IL2CPP_TYPE_U2 or Il2CppTypeEnum.IL2CPP_TYPE_I4 or Il2CppTypeEnum.IL2CPP_TYPE_U4 => "i",
                    Il2CppTypeEnum.IL2CPP_TYPE_I8 or Il2CppTypeEnum.IL2CPP_TYPE_U8 => "j",
                    Il2CppTypeEnum.IL2CPP_TYPE_R4 => "f",
                    Il2CppTypeEnum.IL2CPP_TYPE_R8 => "d",
                    Il2CppTypeEnum.IL2CPP_TYPE_STRING or Il2CppTypeEnum.IL2CPP_TYPE_PTR or Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE or Il2CppTypeEnum.IL2CPP_TYPE_CLASS or Il2CppTypeEnum.IL2CPP_TYPE_VAR or Il2CppTypeEnum.IL2CPP_TYPE_ARRAY or Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST or Il2CppTypeEnum.IL2CPP_TYPE_TYPEDBYREF or Il2CppTypeEnum.IL2CPP_TYPE_I or Il2CppTypeEnum.IL2CPP_TYPE_U or Il2CppTypeEnum.IL2CPP_TYPE_OBJECT or Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY or Il2CppTypeEnum.IL2CPP_TYPE_MVAR => "i",
                    _ => throw new NotSupportedException(),
                };
            }
            return signature;
        }

        private void AddStruct(Il2CppTypeDefinition typeDef)
        {
            var structInfo = new StructInfo();
            structInfoList.Add(structInfo);
            structInfo.TypeName = structNameDic.TryGetValue(typeDef, out var sn) ? sn : FixName(executor.GetTypeDefName(typeDef, true, true));
            structInfo.IsValueType = typeDef.IsValueType;
            AddParents(typeDef, structInfo);
            AddFields(typeDef, structInfo, null);
            AddVTableMethod(structInfo, typeDef);
            AddRGCTX(structInfo, typeDef);
        }

        private void AddGenericClassStruct(ulong pointer)
        {
            try
            {
                var genericClass = il2Cpp.GetGenericClass(pointer);
                var typeDef = executor.GetGenericClassTypeDefinition(genericClass);
                if (typeDef == null) return;
                var structInfo = new StructInfo();
                structInfoList.Add(structInfo);
                structInfo.TypeName = genericClassStructNameDic.TryGetValue(pointer, out var gsn) ? gsn : FixName(executor.GetTypeDefName(typeDef, true, true));
                structInfo.IsValueType = typeDef.IsValueType;
                AddParents(typeDef, structInfo);
                AddFields(typeDef, structInfo, genericClass.context);
                AddVTableMethod(structInfo, typeDef);
            }
            catch { }
        }

        private void AddParents(Il2CppTypeDefinition typeDef, StructInfo structInfo)
        {
            if (!typeDef.IsValueType && !typeDef.IsEnum)
            {
                if (typeDef.parentIndex >= 0 && typeDef.parentIndex < il2Cpp.types.Length)
                {
                    try
                    {
                        var parent = il2Cpp.types[typeDef.parentIndex];
                        if (parent != null && parent.type != Il2CppTypeEnum.IL2CPP_TYPE_OBJECT)
                        {
                            structInfo.Parent = GetIl2CppStructName(parent);
                        }
                    }
                    catch { }
                }
            }
        }

        private void AddFields(Il2CppTypeDefinition typeDef, StructInfo structInfo, Il2CppGenericContext context)
        {
            if (typeDef.field_count > 0)
            {
                var fieldEnd = typeDef.fieldStart + typeDef.field_count;
                var cache = new HashSet<string>(StringComparer.Ordinal);
                for (var i = typeDef.fieldStart; i < fieldEnd; ++i)
                {
                    if (i < 0 || i >= metadata.fieldDefs.Length)
                        continue;
                    try
                    {
                        var fieldDef = metadata.fieldDefs[i];
                        var fieldType = (fieldDef.typeIndex >= 0 && fieldDef.typeIndex < il2Cpp.types.Length) ? il2Cpp.types[fieldDef.typeIndex] : null;
                        if (fieldType == null || (fieldType.attrs & FIELD_ATTRIBUTE_LITERAL) != 0)
                        {
                            continue;
                        }
                        var structFieldInfo = new StructFieldInfo
                        {
                            FieldTypeName = ParseType(fieldType, context)
                        };
                        var fieldName = FixName(metadata.GetStringFromIndex(fieldDef.nameIndex));
                        if (!cache.Add(fieldName))
                        {
                            fieldName = $"_{i - typeDef.fieldStart}_{fieldName}";
                        }
                        structFieldInfo.FieldName = fieldName;
                        structFieldInfo.IsValueType = IsValueType(fieldType, context);
                        structFieldInfo.IsCustomType = IsCustomType(fieldType, context);
                        if ((fieldType.attrs & FIELD_ATTRIBUTE_STATIC) != 0)
                        {
                            structInfo.StaticFields.Add(structFieldInfo);
                        }
                        else
                        {
                            structInfo.Fields.Add(structFieldInfo);
                        }
                    }
                    catch { }
                }
            }
        }

        private void AddVTableMethod(StructInfo structInfo, Il2CppTypeDefinition typeDef)
        {
            if (metadata.vtableMethods == null || typeDef.vtable_count == 0)
                return;
            try
            {
                var dic = new SortedDictionary<int, Il2CppMethodDefinition>();
                for (int i = 0; i < typeDef.vtable_count; i++)
                {
                    var vTableIndex = typeDef.vtableStart + i;
                    if (vTableIndex < 0 || vTableIndex >= metadata.vtableMethods.Length)
                        continue;
                    var encodedMethodIndex = metadata.vtableMethods[vTableIndex];
                    var usage = Metadata.GetEncodedIndexType(encodedMethodIndex);
                    var index = metadata.GetDecodedMethodIndex(encodedMethodIndex);
                    Il2CppMethodDefinition methodDef = null;
                    if (usage == 6 && il2Cpp.methodSpecs != null && index >= 0 && index < il2Cpp.methodSpecs.Length) //kIl2CppMetadataUsageMethodRef
                    {
                        var methodSpec = il2Cpp.methodSpecs[index];
                        if (methodSpec.methodDefinitionIndex >= 0 && methodSpec.methodDefinitionIndex < metadata.methodDefs.Length)
                            methodDef = metadata.methodDefs[methodSpec.methodDefinitionIndex];
                    }
                    else if (index >= 0 && index < metadata.methodDefs.Length)
                    {
                        methodDef = metadata.methodDefs[index];
                    }
                    if (methodDef != null && methodDef.slot != ushort.MaxValue)
                    {
                        dic[methodDef.slot] = methodDef;
                    }
                }
                if (dic.Count > 0)
                {
                    structInfo.VTableMethod = new StructVTableMethodInfo[dic.Last().Key + 1];
                    foreach (var i in dic)
                    {
                        var methodInfo = new StructVTableMethodInfo();
                        structInfo.VTableMethod[i.Key] = methodInfo;
                        var methodDef = i.Value;
                        methodInfo.MethodName = $"{FixName(metadata.GetStringFromIndex(methodDef.nameIndex))}";
                    }
                }
            }
            catch { }
        }

        private void AddRGCTX(StructInfo structInfo, Il2CppTypeDefinition typeDef)
        {
            try
            {
                var imageName = typeDefImageNames.TryGetValue(typeDef, out var iname) ? iname : "";
                var collection = executor.GetRGCTXDefinition(imageName, typeDef);
                if (collection != null)
                {
                    foreach (var definitionData in collection)
                    {
                        var structRGCTXInfo = new StructRGCTXInfo();
                        structInfo.RGCTXs.Add(structRGCTXInfo);
                        structRGCTXInfo.Type = definitionData.type;
                        Il2CppRGCTXDefinitionData rgctxDefData;
                        if (il2Cpp.Version >= 27.2)
                        {
                            rgctxDefData = il2Cpp.MapVATR<Il2CppRGCTXDefinitionData>(definitionData._data);
                        }
                        else
                        {
                            rgctxDefData = definitionData.data;
                        }
                        switch (definitionData.type)
                        {
                            case Il2CppRGCTXDataType.IL2CPP_RGCTX_DATA_TYPE:
                            case Il2CppRGCTXDataType.IL2CPP_RGCTX_DATA_CLASS:
                                {
                                    if (rgctxDefData.typeIndex >= 0 && rgctxDefData.typeIndex < il2Cpp.types.Length)
                                    {
                                        var il2CppType = il2Cpp.types[rgctxDefData.typeIndex];
                                        var tname = FixName(executor.GetTypeName(il2CppType, true, false));
                                        if (definitionData.type == Il2CppRGCTXDataType.IL2CPP_RGCTX_DATA_TYPE)
                                            structRGCTXInfo.TypeName = tname;
                                        else
                                            structRGCTXInfo.ClassName = tname;
                                    }
                                    break;
                                }
                            case Il2CppRGCTXDataType.IL2CPP_RGCTX_DATA_METHOD:
                                {
                                    if (il2Cpp.methodSpecs != null && rgctxDefData.methodIndex >= 0 && rgctxDefData.methodIndex < il2Cpp.methodSpecs.Length)
                                    {
                                        var methodSpec = il2Cpp.methodSpecs[rgctxDefData.methodIndex];
                                        (var methodSpecTypeName, var methodSpecMethodName) = executor.GetMethodSpecName(methodSpec, true);
                                        structRGCTXInfo.MethodName = FixName(methodSpecTypeName + "." + methodSpecMethodName);
                                    }
                                    break;
                                }
                        }
                    }
                }
            }
            catch { }
        }

        private List<StructRGCTXInfo> GenerateRGCTX(string imageName, Il2CppMethodDefinition methodDef)
        {
            var rgctxs = new List<StructRGCTXInfo>();
            try
            {
                var collection = executor.GetRGCTXDefinition(imageName, methodDef);
                if (collection != null)
                {
                    foreach (var definitionData in collection)
                    {
                        var structRGCTXInfo = new StructRGCTXInfo();
                        rgctxs.Add(structRGCTXInfo);
                        structRGCTXInfo.Type = definitionData.type;
                        Il2CppRGCTXDefinitionData rgctxDefData;
                        if (il2Cpp.Version >= 27.2)
                        {
                            rgctxDefData = il2Cpp.MapVATR<Il2CppRGCTXDefinitionData>(definitionData._data);
                        }
                        else
                        {
                            rgctxDefData = definitionData.data;
                        }
                        switch (definitionData.type)
                        {
                            case Il2CppRGCTXDataType.IL2CPP_RGCTX_DATA_TYPE:
                            case Il2CppRGCTXDataType.IL2CPP_RGCTX_DATA_CLASS:
                                {
                                    if (rgctxDefData.typeIndex >= 0 && rgctxDefData.typeIndex < il2Cpp.types.Length)
                                    {
                                        var il2CppType = il2Cpp.types[rgctxDefData.typeIndex];
                                        var tname = FixName(executor.GetTypeName(il2CppType, true, false));
                                        if (definitionData.type == Il2CppRGCTXDataType.IL2CPP_RGCTX_DATA_TYPE)
                                            structRGCTXInfo.TypeName = tname;
                                        else
                                            structRGCTXInfo.ClassName = tname;
                                    }
                                    break;
                                }
                            case Il2CppRGCTXDataType.IL2CPP_RGCTX_DATA_METHOD:
                                {
                                    if (il2Cpp.methodSpecs != null && rgctxDefData.methodIndex >= 0 && rgctxDefData.methodIndex < il2Cpp.methodSpecs.Length)
                                    {
                                        var methodSpec = il2Cpp.methodSpecs[rgctxDefData.methodIndex];
                                        (var methodSpecTypeName, var methodSpecMethodName) = executor.GetMethodSpecName(methodSpec, true);
                                        structRGCTXInfo.MethodName = FixName(methodSpecTypeName + "." + methodSpecMethodName);
                                    }
                                    break;
                                }
                        }
                    }
                }
            }
            catch { }
            return rgctxs;
        }

        private void ParseArrayClassStruct(Il2CppType il2CppType, Il2CppGenericContext context)
        {
            var structName = GetIl2CppStructName(il2CppType, context);
            arrayClassHeader.Append($"struct {structName}_array {{\n" +
                $"\tIl2CppObject obj;\n" +
                $"\tIl2CppArrayBounds *bounds;\n" +
                $"\til2cpp_array_size_t max_length;\n" +
                $"\t{ParseType(il2CppType, context)} m_Items[65535];\n" +
                $"}};\n");
        }

        private Il2CppTypeDefinition GetTypeDefinition(Il2CppType il2CppType)
        {
            switch (il2CppType.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_VOID:
                case Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN:
                case Il2CppTypeEnum.IL2CPP_TYPE_CHAR:
                case Il2CppTypeEnum.IL2CPP_TYPE_I1:
                case Il2CppTypeEnum.IL2CPP_TYPE_U1:
                case Il2CppTypeEnum.IL2CPP_TYPE_I2:
                case Il2CppTypeEnum.IL2CPP_TYPE_U2:
                case Il2CppTypeEnum.IL2CPP_TYPE_I4:
                case Il2CppTypeEnum.IL2CPP_TYPE_U4:
                case Il2CppTypeEnum.IL2CPP_TYPE_I8:
                case Il2CppTypeEnum.IL2CPP_TYPE_U8:
                case Il2CppTypeEnum.IL2CPP_TYPE_R4:
                case Il2CppTypeEnum.IL2CPP_TYPE_R8:
                case Il2CppTypeEnum.IL2CPP_TYPE_STRING:
                case Il2CppTypeEnum.IL2CPP_TYPE_TYPEDBYREF:
                case Il2CppTypeEnum.IL2CPP_TYPE_I:
                case Il2CppTypeEnum.IL2CPP_TYPE_U:
                case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                case Il2CppTypeEnum.IL2CPP_TYPE_CLASS:
                case Il2CppTypeEnum.IL2CPP_TYPE_OBJECT:
                    return executor.GetTypeDefinitionFromIl2CppType(il2CppType);
                case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                    var genericClass = il2Cpp.GetGenericClass(il2CppType);
                    return executor.GetGenericClassTypeDefinition(genericClass);
                default:
                    throw new NotSupportedException();
            }
        }

        private void CreateStructNameDic(Il2CppTypeDefinition typeDef)
        {
            var typeName = executor.GetTypeDefName(typeDef, true, true);
            var typeStructName = FixName(typeName);
            var uniqueName = GetUniqueName(typeStructName);
            structNameDic.Add(typeDef, uniqueName);
        }

        private string GetUniqueName(string name)
        {
            var fixName = name;
            int i = 1;
            while (!structNameHashSet.Add(fixName))
            {
                fixName = $"{name}_{i++}";
            }
            return fixName;
        }

        private string RecursionStructInfo(StructInfo info)
        {
            if (!structCache.Add(info))
            {
                return string.Empty;
            }

            var sb = new StringBuilder();
            var pre = new StringBuilder();

            if (info.Parent != null)
            {
                var parentStructName = info.Parent + "_o";
                if (structInfoWithStructName.TryGetValue(parentStructName, out var parentInfo))
                {
                    pre.Append(RecursionStructInfo(parentInfo));
                }
                sb.Append($"struct {info.TypeName}_Fields : {info.Parent}_Fields {{\n");
                // C style
                //sb.Append($"struct {info.TypeName}_Fields {{\n");
                //sb.Append($"\t{info.Parent}_Fields _;\n");
            }
            else
            {
                if (il2Cpp is PE && !info.IsValueType)
                {
                    if (il2Cpp.Is32Bit)
                    {
                        sb.Append($"struct __declspec(align(4)) {info.TypeName}_Fields {{\n");
                    }
                    else
                    {
                        sb.Append($"struct __declspec(align(8)) {info.TypeName}_Fields {{\n");
                    }
                }
                else
                {
                    sb.Append($"struct {info.TypeName}_Fields {{\n");
                }
            }
            foreach (var field in info.Fields)
            {
                if (field.IsValueType)
                {
                    if (structInfoWithStructName.TryGetValue(field.FieldTypeName, out var fieldInfo))
                    {
                        pre.Append(RecursionStructInfo(fieldInfo));
                    }
                }
                if (field.IsCustomType)
                {
                    sb.Append($"\tstruct {field.FieldTypeName} {field.FieldName};\n");
                }
                else
                {
                    sb.Append($"\t{field.FieldTypeName} {field.FieldName};\n");
                }
            }
            sb.Append("};\n");

            if (info.RGCTXs.Count > 0)
            {
                sb.Append($"struct {info.TypeName}_RGCTXs {{\n");
                for (int i = 0; i < info.RGCTXs.Count; i++)
                {
                    var rgctx = info.RGCTXs[i];
                    switch (rgctx.Type)
                    {
                        case Il2CppRGCTXDataType.IL2CPP_RGCTX_DATA_TYPE:
                            sb.Append($"\tIl2CppType* _{i}_{rgctx.TypeName};\n");
                            break;
                        case Il2CppRGCTXDataType.IL2CPP_RGCTX_DATA_CLASS:
                            sb.Append($"\tIl2CppClass* _{i}_{rgctx.ClassName};\n");
                            break;
                        case Il2CppRGCTXDataType.IL2CPP_RGCTX_DATA_METHOD:
                            sb.Append($"\tMethodInfo* _{i}_{rgctx.MethodName};\n");
                            break;
                    }
                }
                sb.Append("};\n");
            }

            if (info.VTableMethod.Length > 0)
            {
                sb.Append($"struct {info.TypeName}_VTable {{\n");
                for (int i = 0; i < info.VTableMethod.Length; i++)
                {
                    sb.Append($"\tVirtualInvokeData _{i}_");
                    var method = info.VTableMethod[i];
                    if (method != null)
                    {
                        sb.Append(method.MethodName);
                    }
                    else
                    {
                        sb.Append("unknown");
                    }
                    sb.Append(";\n");
                }
                sb.Append("};\n");
            }

            sb.Append($"struct {info.TypeName}_c {{\n");
            sb.Append($"\tIl2CppClass_1 _1;\n");
            if (info.StaticFields.Count > 0)
            {
                sb.Append($"\tstruct {info.TypeName}_StaticFields* static_fields;\n");
            }
            else
            {
                sb.Append("\tvoid* static_fields;\n");
            }
            if (info.RGCTXs.Count > 0)
            {
                sb.Append($"\t{info.TypeName}_RGCTXs* rgctx_data;\n");
            }
            else
            {
                sb.Append("\tIl2CppRGCTXData* rgctx_data;\n");
            }
            sb.Append($"\tIl2CppClass_2 _2;\n");
            if (info.VTableMethod.Length > 0)
            {
                sb.Append($"\t{info.TypeName}_VTable vtable;\n");
            }
            else
            {
                sb.Append("\tVirtualInvokeData vtable[32];\n");
            }
            sb.Append($"}};\n");

            sb.Append($"struct {info.TypeName}_o {{\n");
            if (!info.IsValueType)
            {
                sb.Append($"\t{info.TypeName}_c *klass;\n");
                sb.Append($"\tvoid *monitor;\n");
            }
            sb.Append($"\t{info.TypeName}_Fields fields;\n");
            sb.Append("};\n");

            if (info.StaticFields.Count > 0)
            {
                sb.Append($"struct {info.TypeName}_StaticFields {{\n");
                foreach (var field in info.StaticFields)
                {
                    if (field.IsValueType)
                    {
                        if (structInfoWithStructName.TryGetValue(field.FieldTypeName, out var fieldInfo))
                        {
                            pre.Append(RecursionStructInfo(fieldInfo));
                        }
                    }
                    if (field.IsCustomType)
                    {
                        sb.Append($"\tstruct {field.FieldTypeName} {field.FieldName};\n");
                    }
                    else
                    {
                        sb.Append($"\t{field.FieldTypeName} {field.FieldName};\n");
                    }
                }
                sb.Append("};\n");
            }

            return pre.Append(sb).ToString();
        }

        private string GetIl2CppStructName(Il2CppType il2CppType, Il2CppGenericContext context = null)
        {
            switch (il2CppType.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_VOID:
                case Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN:
                case Il2CppTypeEnum.IL2CPP_TYPE_CHAR:
                case Il2CppTypeEnum.IL2CPP_TYPE_I1:
                case Il2CppTypeEnum.IL2CPP_TYPE_U1:
                case Il2CppTypeEnum.IL2CPP_TYPE_I2:
                case Il2CppTypeEnum.IL2CPP_TYPE_U2:
                case Il2CppTypeEnum.IL2CPP_TYPE_I4:
                case Il2CppTypeEnum.IL2CPP_TYPE_U4:
                case Il2CppTypeEnum.IL2CPP_TYPE_I8:
                case Il2CppTypeEnum.IL2CPP_TYPE_U8:
                case Il2CppTypeEnum.IL2CPP_TYPE_R4:
                case Il2CppTypeEnum.IL2CPP_TYPE_R8:
                case Il2CppTypeEnum.IL2CPP_TYPE_STRING:
                case Il2CppTypeEnum.IL2CPP_TYPE_TYPEDBYREF:
                case Il2CppTypeEnum.IL2CPP_TYPE_I:
                case Il2CppTypeEnum.IL2CPP_TYPE_U:
                case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                case Il2CppTypeEnum.IL2CPP_TYPE_CLASS:
                case Il2CppTypeEnum.IL2CPP_TYPE_OBJECT:
                    {
                        var typeDef = executor.GetTypeDefinitionFromIl2CppType(il2CppType);
                        if (typeDef != null && structNameDic.TryGetValue(typeDef, out var sn))
                            return sn;
                        return "System_Object";
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_PTR:
                    {
                        var oriType = il2Cpp.ResolveType(il2CppType.data.type);
                        return GetIl2CppStructName(oriType);
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_ARRAY:
                    {
                        var arrayType = il2Cpp.MapVATR<Il2CppArrayType>(il2CppType.data.array);
                        var elementType = il2Cpp.ResolveType(arrayType.etype);
                        var elementStructName = GetIl2CppStructName(elementType, context);
                        var typeStructName = elementStructName + "_array";
                        if (structNameHashSet.Add(typeStructName))
                        {
                            ParseArrayClassStruct(elementType, context);
                        }
                        return typeStructName;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
                    {
                        var elementType = il2Cpp.ResolveType(il2CppType.data.type);
                        var elementStructName = GetIl2CppStructName(elementType, context);
                        var typeStructName = elementStructName + "_array";
                        if (structNameHashSet.Add(typeStructName))
                        {
                            ParseArrayClassStruct(elementType, context);
                        }
                        return typeStructName;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                    {
                        var typeStructName = genericClassStructNameDic[il2CppType.data.generic_class];
                        if (structNameHashSet.Add(typeStructName))
                        {
                            genericClassList.Add(il2CppType.data.generic_class);
                        }
                        return typeStructName;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_VAR:
                    {
                        if (context != null)
                        {
                            var genericParameter = executor.GetGenericParameteFromIl2CppType(il2CppType);
                            var genericInst = il2Cpp.MapVATR<Il2CppGenericInst>(context.class_inst);
                            var pointers = il2Cpp.MapVATR<ulong>(genericInst.type_argv, genericInst.type_argc);
                            var pointer = pointers[genericParameter.num];
                            var type = il2Cpp.GetIl2CppType(pointer);
                            return GetIl2CppStructName(type);
                        }
                        return "System_Object";
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_MVAR:
                    {
                        if (context != null)
                        {
                            var genericParameter = executor.GetGenericParameteFromIl2CppType(il2CppType);
                            var genericInst = il2Cpp.MapVATR<Il2CppGenericInst>(context.method_inst);
                            var pointers = il2Cpp.MapVATR<ulong>(genericInst.type_argv, genericInst.type_argc);
                            var pointer = pointers[genericParameter.num];
                            var type = il2Cpp.GetIl2CppType(pointer);
                            return GetIl2CppStructName(type);
                        }
                        return "System_Object";
                    }
                default:
                    throw new NotSupportedException();
            }
        }

        private bool IsValueType(Il2CppType il2CppType, Il2CppGenericContext context)
        {
            switch (il2CppType.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                    {
                        var typeDef = executor.GetTypeDefinitionFromIl2CppType(il2CppType);
                        return !typeDef.IsEnum;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                    {
                        var genericClass = il2Cpp.GetGenericClass(il2CppType);
                        var typeDef = executor.GetGenericClassTypeDefinition(genericClass);
                        return typeDef.IsValueType && !typeDef.IsEnum;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_VAR:
                    {
                        if (context != null)
                        {
                            var genericParameter = executor.GetGenericParameteFromIl2CppType(il2CppType);
                            var genericInst = il2Cpp.MapVATR<Il2CppGenericInst>(context.class_inst);
                            var pointers = il2Cpp.MapVATR<ulong>(genericInst.type_argv, genericInst.type_argc);
                            var pointer = pointers[genericParameter.num];
                            var type = il2Cpp.GetIl2CppType(pointer);
                            return IsValueType(type, null);
                        }
                        return false;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_MVAR:
                    {
                        if (context != null)
                        {
                            var genericParameter = executor.GetGenericParameteFromIl2CppType(il2CppType);
                            var genericInst = il2Cpp.MapVATR<Il2CppGenericInst>(context.method_inst);
                            var pointers = il2Cpp.MapVATR<ulong>(genericInst.type_argv, genericInst.type_argc);
                            var pointer = pointers[genericParameter.num];
                            var type = il2Cpp.GetIl2CppType(pointer);
                            return IsValueType(type, null);
                        }
                        return false;
                    }
                default:
                    return false;
            }
        }

        private bool IsCustomType(Il2CppType il2CppType, Il2CppGenericContext context)
        {
            switch (il2CppType.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_PTR:
                    {
                        var oriType = il2Cpp.ResolveType(il2CppType.data.type);
                        return IsCustomType(oriType, context);
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_STRING:
                case Il2CppTypeEnum.IL2CPP_TYPE_CLASS:
                case Il2CppTypeEnum.IL2CPP_TYPE_ARRAY:
                case Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
                    {
                        return true;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                    {
                        var typeDef = executor.GetTypeDefinitionFromIl2CppType(il2CppType);
                        if (typeDef != null && typeDef.IsEnum)
                        {
                            var elemIdx = typeDef.GetEnumElementTypeIndex(il2Cpp.Version);
                            if (elemIdx >= 0 && elemIdx < il2Cpp.types.Length)
                            {
                                return IsCustomType(il2Cpp.types[elemIdx], context);
                            }
                            return false;
                        }
                        return true;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                    {
                        var genericClass = il2Cpp.GetGenericClass(il2CppType);
                        var typeDef = executor.GetGenericClassTypeDefinition(genericClass);
                        if (typeDef != null && typeDef.IsEnum)
                        {
                            var elemIdx = typeDef.GetEnumElementTypeIndex(il2Cpp.Version);
                            if (elemIdx >= 0 && elemIdx < il2Cpp.types.Length)
                            {
                                return IsCustomType(il2Cpp.types[elemIdx], context);
                            }
                            return false;
                        }
                        return true;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_VAR:
                case Il2CppTypeEnum.IL2CPP_TYPE_MVAR:
                    {
                        if (context != null)
                        {
                            var genericParameter = executor.GetGenericParameteFromIl2CppType(il2CppType);
                            if (context.method_inst != 0)
                            {
                                // Is method
                                var genericInst = il2Cpp.MapVATR<Il2CppGenericInst>(context.method_inst);
                                var pointers = il2Cpp.MapVATR<ulong>(genericInst.type_argv, genericInst.type_argc);
                                var pointer = pointers[genericParameter.num];
                                var type = il2Cpp.GetIl2CppType(pointer);
                                return IsCustomType(type, null);
                            } else if (context.class_inst != 0)
                            {
                                // Is class
                                var genericInst = il2Cpp.MapVATR<Il2CppGenericInst>(context.class_inst);
                                var pointers = il2Cpp.MapVATR<ulong>(genericInst.type_argv, genericInst.type_argc);
                                var pointer = pointers[genericParameter.num];
                                var type = il2Cpp.GetIl2CppType(pointer);
                                return IsCustomType(type, null);
                            }
                        }
                        return false;
                    }
                default:
                    return false;
            }
        }

        private void GenerateMethodInfo(string methodInfoName, string structTypeName, List<StructRGCTXInfo> rgctxs)
        {
            if (rgctxs.Count > 0)
            {
                methodInfoHeader.Append($"struct {methodInfoName}_RGCTXs {{\n");
                for (int i = 0; i < rgctxs.Count; i++)
                {
                    var rgctx = rgctxs[i];
                    switch (rgctx.Type)
                    {
                        case Il2CppRGCTXDataType.IL2CPP_RGCTX_DATA_TYPE:
                            methodInfoHeader.Append($"\tIl2CppType* _{i}_{rgctx.TypeName};\n");
                            break;
                        case Il2CppRGCTXDataType.IL2CPP_RGCTX_DATA_CLASS:
                            methodInfoHeader.Append($"\tIl2CppClass* _{i}_{rgctx.ClassName};\n");
                            break;
                        case Il2CppRGCTXDataType.IL2CPP_RGCTX_DATA_METHOD:
                            methodInfoHeader.Append($"\tMethodInfo* _{i}_{rgctx.MethodName};\n");
                            break;
                    }
                }
                methodInfoHeader.Append("};\n");
            }

            methodInfoHeader.Append($"struct {methodInfoName} {{\n");
            methodInfoHeader.Append($"\tIl2CppMethodPointer methodPointer;\n");
            if (il2Cpp.Version >= 29)
            {
                methodInfoHeader.Append($"\tIl2CppMethodPointer virtualMethodPointer;\n");
                methodInfoHeader.Append($"\tInvokerMethod invoker_method;\n");
            }
            else
            {
                methodInfoHeader.Append($"\tvoid* invoker_method;\n"); //TODO
            }
            methodInfoHeader.Append($"\tconst char* name;\n");
            if (il2Cpp.Version <= 24)
            {
                methodInfoHeader.Append($"\t{structTypeName}_c *declaring_type;\n");
            }
            else
            {
                methodInfoHeader.Append($"\t{structTypeName}_c *klass;\n");
            }
            methodInfoHeader.Append($"\tconst Il2CppType *return_type;\n");
            if (il2Cpp.Version >= 29)
            {
                methodInfoHeader.Append($"\tconst Il2CppType** parameters;\n");
            }
            else
            {
                methodInfoHeader.Append($"\tconst void* parameters;\n"); //ParameterInfo*
            }
            if (rgctxs.Count > 0)
            {
                methodInfoHeader.Append($"\tconst {methodInfoName}_RGCTXs* rgctx_data;\n");
            }
            else
            {
                methodInfoHeader.Append($"\tconst Il2CppRGCTXData* rgctx_data;\n");
            }
            methodInfoHeader.Append($"\tunion\n");
            methodInfoHeader.Append($"\t{{\n");
            methodInfoHeader.Append($"\t\tconst void* genericMethod;\n");
            if (il2Cpp.Version >= 27)
            {
                methodInfoHeader.Append($"\t\tconst void* genericContainerHandle;\n");
            }
            else
            {
                methodInfoHeader.Append($"\t\tconst void* genericContainer;\n");
            }
            methodInfoHeader.Append($"\t}};\n");
            if (il2Cpp.Version <= 24)
            {
                methodInfoHeader.Append($"\tint32_t customAttributeIndex;\n");
            }
            methodInfoHeader.Append($"\tuint32_t token;\n");
            methodInfoHeader.Append($"\tuint16_t flags;\n");
            methodInfoHeader.Append($"\tuint16_t iflags;\n");
            methodInfoHeader.Append($"\tuint16_t slot;\n");
            methodInfoHeader.Append($"\tuint8_t parameters_count;\n");
            methodInfoHeader.Append($"\tuint8_t bitflags;\n");
            methodInfoHeader.Append($"}};\n");
        }
    }
}
