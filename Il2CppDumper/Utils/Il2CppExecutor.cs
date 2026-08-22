using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    public class Il2CppExecutor
    {
        public Metadata metadata;
        public Il2Cpp il2Cpp;
        private static readonly Dictionary<int, string> TypeString = new()
        {
            {1,"void"},
            {2,"bool"},
            {3,"char"},
            {4,"sbyte"},
            {5,"byte"},
            {6,"short"},
            {7,"ushort"},
            {8,"int"},
            {9,"uint"},
            {10,"long"},
            {11,"ulong"},
            {12,"float"},
            {13,"double"},
            {14,"string"},
            {22,"TypedReference"},
            {24,"IntPtr"},
            {25,"UIntPtr"},
            {28,"object"},
        };
        public ulong[] customAttributeGenerators;
        public readonly Dictionary<int, Il2CppTypeDefinition> typeIndexToTypeDef = new();

        public Il2CppExecutor(Metadata metadata, Il2Cpp il2Cpp)
        {
            this.metadata = metadata;
            this.il2Cpp = il2Cpp;

            if (metadata.typeDefs != null)
            {
                foreach (var td in metadata.typeDefs)
                {
                    typeIndexToTypeDef[(int)td.byvalTypeIndex] = td;
                    if (td.byrefTypeIndex >= 0)
                        typeIndexToTypeDef[td.byrefTypeIndex] = td;
                }
            }

            if (il2Cpp.Version >= 27 && il2Cpp.Version < 29)
            {
                customAttributeGenerators = new ulong[metadata.imageDefs.Sum(x => x.customAttributeCount)];
                foreach (var imageDef in metadata.imageDefs)
                {
                    var imageDefName = metadata.GetStringFromIndex(imageDef.nameIndex);
                    var codeGenModule = il2Cpp.codeGenModules[imageDefName];
                    if (imageDef.customAttributeCount > 0)
                    {
                        var pointers = il2Cpp.ReadClassArray<ulong>(il2Cpp.MapVATR(codeGenModule.customAttributeCacheGenerator), imageDef.customAttributeCount);
                        pointers.CopyTo(customAttributeGenerators, imageDef.customAttributeStart);
                    }
                }
            }
            else if (il2Cpp.Version < 27)
            {
                customAttributeGenerators = il2Cpp.customAttributeGenerators;
            }
        }

        public string GetTypeNameFromIndex(int typeIndex, bool addNamespace = false)
        {
            if (typeIndex == -1 || typeIndex == 392904)
                return "void";
            if (typeIndexToTypeDef.TryGetValue(typeIndex, out var td))
            {
                return GetTypeDefName(td, addNamespace, false);
            }
            if (il2Cpp.types != null && typeIndex >= 0 && typeIndex < il2Cpp.types.Length)
            {
                return GetTypeName(il2Cpp.types[typeIndex], addNamespace, false);
            }
            return "object";
        }

        public string GetTypeName(Il2CppType il2CppType, bool addNamespace, bool is_nested)
        {
            if (il2CppType == null)
                return "object";
            try
            {
                switch (il2CppType.type)
                {
                    case Il2CppTypeEnum.IL2CPP_TYPE_ARRAY:
                        {
                            var arrayType = il2Cpp.MapVATR<Il2CppArrayType>(il2CppType.datapoint);
                            var elementType = il2Cpp.ResolveType(arrayType.etype);
                            var elementName = elementType != null ? GetTypeName(elementType, addNamespace, false) : "object";
                            var rank = Math.Max(arrayType.rank, (byte)1);
                            return $"{elementName}[{string.Join(", ", Enumerable.Repeat(string.Empty, rank))}]";
                        }
                    case Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
                        {
                            var elementType = il2Cpp.ResolveType(il2CppType.datapoint);
                            var elemName = elementType != null ? GetTypeName(elementType, addNamespace, false) : "object";
                            return $"{elemName}[]";
                        }
                    case Il2CppTypeEnum.IL2CPP_TYPE_PTR:
                        {
                            var oriType = il2Cpp.ResolveType(il2CppType.datapoint);
                            var elemName = oriType != null ? GetTypeName(oriType, addNamespace, false) : "void";
                            return $"{elemName}*";
                        }
                    case Il2CppTypeEnum.IL2CPP_TYPE_VAR:
                    case Il2CppTypeEnum.IL2CPP_TYPE_MVAR:
                        {
                            var param = GetGenericParameteFromIl2CppType(il2CppType);
                            return param != null ? metadata.GetStringFromIndex(param.nameIndex) : "T";
                        }
                    case Il2CppTypeEnum.IL2CPP_TYPE_CLASS:
                    case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                        {
                            var idx = (int)il2CppType.datapoint;
                            if (idx >= 0 && idx < metadata.typeDefs.Length)
                            {
                                var typeDef = metadata.typeDefs[idx];
                                return GetTypeDefName(typeDef, addNamespace, true);
                            }
                            if (TypeString.TryGetValue((int)il2CppType.type, out var tstr))
                                return tstr;
                            return "object";
                        }
                    case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                        {
                            var idx = (int)il2CppType.datapoint;
                            var gc = il2Cpp.GetGenericClass(il2CppType);
                            if (gc != null)
                            {
                                var typeDefIdx = (int)gc.typeDefinitionIndex;
                                if (typeDefIdx >= 0 && typeDefIdx < metadata.typeDefs.Length)
                                {
                                    var baseName = GetTypeDefName(metadata.typeDefs[typeDefIdx], addNamespace, false);
                                    var arityMarker = baseName.LastIndexOf('`');
                                    if (arityMarker >= 0)
                                    {
                                        baseName = baseName[..arityMarker];
                                    }
                                    if (gc.context?.class_inst > 0)
                                    {
                                        try
                                        {
                                            var inst = il2Cpp.MapVATR<Il2CppGenericInst>(gc.context.class_inst);
                                            var pointers = il2Cpp.MapVATR<ulong>(inst.type_argv, inst.type_argc);
                                            var arguments = pointers
                                                .Select(pointer => il2Cpp.GetIl2CppType(pointer))
                                                .Select(type => GetTypeName(type, addNamespace, false));
                                            return $"{baseName}<{string.Join(", ", arguments)}>";
                                        }
                                        catch { }
                                    }
                                    return GetTypeDefName(metadata.typeDefs[typeDefIdx], addNamespace, true);
                                }
                            }
                            if (idx >= 0 && idx < metadata.typeDefs.Length)
                            {
                                return GetTypeDefName(metadata.typeDefs[idx], addNamespace, true);
                            }
                            return "object";
                        }
                    default:
                        if (TypeString.TryGetValue((int)il2CppType.type, out var tname))
                            return tname;
                        return "object";
                }
            }
            catch
            {
                return "object";
            }
        }

        public string GetTypeDefName(Il2CppTypeDefinition typeDef, bool addNamespace, bool genericParameter, bool usePrimitiveAliases = true)
        {
            var prefix = string.Empty;
            var @namespace = metadata.GetStringFromIndex(typeDef.namespaceIndex);
            var typeName = metadata.GetStringFromIndex(typeDef.nameIndex);
            if (usePrimitiveAliases && !addNamespace && (@namespace == "System" || string.IsNullOrEmpty(@namespace)))
            {
                switch (typeName)
                {
                    case "Void": return "void";
                    case "Boolean": return "bool";
                    case "Char": return "char";
                    case "Byte": return "byte";
                    case "SByte": return "sbyte";
                    case "Int16": return "short";
                    case "UInt16": return "ushort";
                    case "Int32": return "int";
                    case "UInt32": return "uint";
                    case "Int64": return "long";
                    case "UInt64": return "ulong";
                    case "Single": return "float";
                    case "Double": return "double";
                    case "String": return "string";
                    case "Object": return "object";
                }
            }
            if (addNamespace && typeDef.declaringTypeIndex >= 0 && typeDef.declaringTypeIndex < il2Cpp.types.Length)
            {
                try
                {
                    var declType = il2Cpp.types[typeDef.declaringTypeIndex];
                    if (declType != null)
                        prefix = GetTypeName(declType, addNamespace, true) + ".";
                }
                catch { }
            }
            else if (addNamespace)
            {
                if (@namespace != "")
                {
                    prefix = @namespace + ".";
                }
            }
            if (typeDef.genericContainerIndex >= 0 && metadata.genericContainers != null && typeDef.genericContainerIndex < metadata.genericContainers.Length)
            {
                var arityMarker = typeName.IndexOf('`');
                if (arityMarker >= 0)
                {
                    typeName = typeName[..arityMarker];
                }
                if (genericParameter)
                {
                    var genericContainer = metadata.genericContainers[typeDef.genericContainerIndex];
                    typeName += GetGenericContainerParams(genericContainer);
                }
            }
            return prefix + typeName;
        }

        public string GetGenericInstParams(Il2CppGenericInst genericInst)
        {
            var genericParameterNames = new List<string>();
            var pointers = il2Cpp.MapVATR<ulong>(genericInst.type_argv, genericInst.type_argc);
            for (int i = 0; i < genericInst.type_argc; i++)
            {
                var il2CppType = il2Cpp.GetIl2CppType(pointers[i]);
                genericParameterNames.Add(GetTypeName(il2CppType, false, false));
            }
            return $"<{string.Join(", ", genericParameterNames)}>";
        }

        public string GetGenericContainerParams(Il2CppGenericContainer genericContainer)
        {
            var genericParameterNames = new List<string>();
            if (genericContainer != null && metadata.genericParameters != null)
            {
                for (int i = 0; i < genericContainer.type_argc; i++)
                {
                    var genericParameterIndex = genericContainer.genericParameterStart + i;
                    if (genericParameterIndex >= 0 && genericParameterIndex < metadata.genericParameters.Length)
                    {
                        var genericParameter = metadata.genericParameters[genericParameterIndex];
                        genericParameterNames.Add(metadata.GetStringFromIndex(genericParameter.nameIndex));
                    }
                    else
                    {
                        genericParameterNames.Add($"T{i}");
                    }
                }
            }
            return $"<{string.Join(", ", genericParameterNames)}>";
        }

        public (string, string) GetMethodSpecName(Il2CppMethodSpec methodSpec, bool addNamespace = false)
        {
            if (methodSpec == null || methodSpec.methodDefinitionIndex < 0 || methodSpec.methodDefinitionIndex >= metadata.methodDefs.Length)
                return ("Unknown", "Unknown");
            var methodDef = metadata.methodDefs[methodSpec.methodDefinitionIndex];
            var typeDef = (methodDef.declaringType >= 0 && methodDef.declaringType < metadata.typeDefs.Length) ? metadata.typeDefs[methodDef.declaringType] : null;
            var typeName = typeDef != null ? GetTypeDefName(typeDef, addNamespace, false) : "UnknownType";
            if (methodSpec.classIndexIndex != -1 && methodSpec.classIndexIndex < il2Cpp.genericInsts.Length)
            {
                var classInst = il2Cpp.genericInsts[methodSpec.classIndexIndex];
                if (classInst != null)
                    typeName += GetGenericInstParams(classInst);
            }
            var methodName = metadata.GetStringFromIndex(methodDef.nameIndex);
            if (methodSpec.methodIndexIndex != -1 && methodSpec.methodIndexIndex < il2Cpp.genericInsts.Length)
            {
                var methodInst = il2Cpp.genericInsts[methodSpec.methodIndexIndex];
                if (methodInst != null)
                    methodName += GetGenericInstParams(methodInst);
            }
            return (typeName, methodName);
        }

        public Il2CppGenericContext GetMethodSpecGenericContext(Il2CppMethodSpec methodSpec)
        {
            var classInstPointer = 0ul;
            var methodInstPointer = 0ul;
            if (methodSpec.classIndexIndex != -1)
            {
                classInstPointer = il2Cpp.genericInstPointers[methodSpec.classIndexIndex];
            }
            if (methodSpec.methodIndexIndex != -1)
            {
                methodInstPointer = il2Cpp.genericInstPointers[methodSpec.methodIndexIndex];
            }
            return new Il2CppGenericContext { class_inst = classInstPointer, method_inst = methodInstPointer };
        }

        public Il2CppRGCTXDefinition[] GetRGCTXDefinition(string imageName, Il2CppTypeDefinition typeDef)
        {
            Il2CppRGCTXDefinition[] collection = null;
            if (il2Cpp.Version >= 24.2)
            {
                if (il2Cpp.rgctxsDictionary != null && il2Cpp.rgctxsDictionary.TryGetValue(imageName, out var dic))
                {
                    dic.TryGetValue(typeDef.token, out collection);
                }
            }
            else
            {
                if (typeDef.rgctxCount > 0 && metadata.rgctxEntries != null && typeDef.rgctxStartIndex + typeDef.rgctxCount <= metadata.rgctxEntries.Length)
                {
                    collection = new Il2CppRGCTXDefinition[typeDef.rgctxCount];
                    Array.Copy(metadata.rgctxEntries, typeDef.rgctxStartIndex, collection, 0, typeDef.rgctxCount);
                }
            }
            return collection;
        }

        public Il2CppRGCTXDefinition[] GetRGCTXDefinition(string imageName, Il2CppMethodDefinition methodDef)
        {
            Il2CppRGCTXDefinition[] collection = null;
            if (il2Cpp.Version >= 24.2)
            {
                if (il2Cpp.rgctxsDictionary != null && il2Cpp.rgctxsDictionary.TryGetValue(imageName, out var dic))
                {
                    dic.TryGetValue(methodDef.token, out collection);
                }
            }
            else
            {
                if (methodDef.rgctxCount > 0 && metadata.rgctxEntries != null && methodDef.rgctxStartIndex + methodDef.rgctxCount <= metadata.rgctxEntries.Length)
                {
                    collection = new Il2CppRGCTXDefinition[methodDef.rgctxCount];
                    Array.Copy(metadata.rgctxEntries, methodDef.rgctxStartIndex, collection, 0, methodDef.rgctxCount);
                }
            }
            return collection;
        }

        public Il2CppTypeDefinition GetGenericClassTypeDefinition(Il2CppGenericClass genericClass)
        {
            if (genericClass == null)
                return null;
            try
            {
                if (genericClass.type > 0)
                {
                    var il2CppType = il2Cpp.GetIl2CppType(genericClass.type);
                    if (il2CppType != null)
                    {
                        return GetTypeDefinitionFromIl2CppType(il2CppType);
                    }
                }
                var idx = genericClass.typeDefinitionIndex;
                if (idx >= 0 && idx < metadata.typeDefs.Length)
                {
                    return metadata.typeDefs[idx];
                }
            }
            catch { }
            return metadata.typeDefs.Length > 0 ? metadata.typeDefs[0] : null;
        }

        public Il2CppTypeDefinition GetTypeDefinitionFromIl2CppType(Il2CppType il2CppType)
        {
            if (il2CppType == null || il2CppType.data == null)
                return null;
            if (il2Cpp.Version >= 27 && il2Cpp.IsDumped)
            {
                try
                {
                    var offset = il2CppType.data.typeHandle - metadata.ImageBase - (il2Cpp.Version < 38 ? metadata.header.typeDefinitionsOffset : metadata.header.typeDefinitions.offset);
                    var index = offset / (ulong)metadata.SizeOf(typeof(Il2CppTypeDefinition));
                    if (index < (ulong)metadata.typeDefs.Length)
                        return metadata.typeDefs[index];
                }
                catch { }
                return metadata.typeDefs.Length > 0 ? metadata.typeDefs[0] : null;
            }
            else
            {
                var idx = il2CppType.data.klassIndex;
                if (idx >= 0 && idx < metadata.typeDefs.Length)
                    return metadata.typeDefs[idx];
                return metadata.typeDefs.Length > 0 ? metadata.typeDefs[0] : null;
            }
        }

        public Il2CppGenericParameter GetGenericParameteFromIl2CppType(Il2CppType il2CppType)
        {
            if (il2CppType == null || il2CppType.data == null)
                return null;
            if (il2Cpp.Version >= 27 && il2Cpp.IsDumped)
            {
                try
                {
                    var offset = il2CppType.data.genericParameterHandle - metadata.ImageBase - (il2Cpp.Version < 38 ? metadata.header.genericParametersOffset : metadata.header.genericParameters.offset);
                    var index = offset / (ulong)metadata.SizeOf(typeof(Il2CppGenericParameter));
                    if (index < (ulong)metadata.genericParameters.Length)
                        return metadata.genericParameters[index];
                }
                catch { }
                return null;
            }
            else
            {
                var idx = il2CppType.data.genericParameterIndex;
                if (idx >= 0 && metadata.genericParameters != null && idx < metadata.genericParameters.Length)
                    return metadata.genericParameters[idx];
                return null;
            }
        }

        public SectionHelper GetSectionHelper()
        {
            return il2Cpp.GetSectionHelper(metadata.methodDefs.Count(x => x.methodIndex >= 0), metadata.typeDefs.Length, metadata.imageDefs.Length);
        }

        public bool TryGetDefaultValue(int typeIndex, int dataIndex, out object value)
        {
            var pointer = metadata.GetDefaultValueFromIndex(dataIndex);
            value = pointer;
            if (typeIndex < 0 || typeIndex >= il2Cpp.types.Length || pointer >= metadata.Length)
            {
                return false;
            }
            try
            {
                var defaultValueType = il2Cpp.types[typeIndex];
                if (defaultValueType == null)
                {
                    return false;
                }
                metadata.Position = pointer;
                if (!GetConstantValueFromBlob(defaultValueType.type, metadata.Reader, out var blobValue))
                {
                    return false;
                }
                var constant = blobValue.Value;
                if (constant != null && constant is not string && !constant.GetType().IsPrimitive)
                {
                    return false;
                }
                value = constant;
                return true;
            }
            catch (EndOfStreamException)
            {
                return false;
            }
            catch (IndexOutOfRangeException)
            {
                return false;
            }
            catch (FormatException)
            {
                return false;
            }
            catch (InvalidDataException)
            {
                return false;
            }
        }

        public bool GetConstantValueFromBlob(Il2CppTypeEnum type, BinaryReader reader, out BlobValue value)
        {
            value = new BlobValue
            {
                il2CppTypeEnum = type
            };
            switch (type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN:
                    value.Value = reader.ReadBoolean();
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_U1:
                    value.Value = reader.ReadByte();
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_I1:
                    value.Value = reader.ReadSByte();
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_CHAR:
                    value.Value = BitConverter.ToChar(reader.ReadBytes(2), 0);
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_U2:
                    value.Value = reader.ReadUInt16();
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_I2:
                    value.Value = reader.ReadInt16();
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_U4:
                    if (il2Cpp.Version >= 29)
                    {
                        value.Value = reader.ReadCompressedUInt32();
                    }
                    else
                    {
                        value.Value = reader.ReadUInt32();
                    }
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_I4:
                    if (il2Cpp.Version >= 29)
                    {
                        value.Value = reader.ReadCompressedInt32();
                    }
                    else
                    {
                        value.Value = reader.ReadInt32();
                    }
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_U8:
                    value.Value = reader.ReadUInt64();
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_I8:
                    value.Value = reader.ReadInt64();
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_R4:
                    value.Value = reader.ReadSingle();
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_R8:
                    value.Value = reader.ReadDouble();
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_STRING:
                    int length;
                    if (il2Cpp.Version >= 29)
                    {
                        length = reader.ReadCompressedInt32();
                        if (length == -1)
                        {
                            value.Value = null;
                        }
                        else
                        {
                            value.Value = Encoding.UTF8.GetString(reader.ReadBytes(length));
                        }
                    }
                    else
                    {
                        length = reader.ReadInt32();
                        value.Value = reader.ReadString(length);
                    }
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
                    var arrayLen = reader.ReadCompressedInt32();
                    if (arrayLen == -1)
                    {
                        value.Value = null;
                    }
                    else
                    {
                        var array = new BlobValue[arrayLen];
                        var arrayElementType = ReadEncodedTypeEnum(reader, out var enumType);
                        var arrayElementsAreDifferent = reader.ReadByte();
                        for (int i = 0; i < arrayLen; i++)
                        {
                            var elementType = arrayElementType;
                            if (arrayElementsAreDifferent == 1)
                            {
                                elementType = ReadEncodedTypeEnum(reader, out enumType);
                            }
                            GetConstantValueFromBlob(elementType, reader, out var data);
                            data.il2CppTypeEnum = elementType;
                            data.EnumType = enumType;
                            array[i] = data;
                        }
                        value.Value = array;
                    }
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_IL2CPP_TYPE_INDEX:
                    var typeIndex = reader.ReadCompressedInt32();
                    if (typeIndex == -1)
                    {
                        value.Value = null;
                    }
                    else
                    {
                        value.Value = il2Cpp.types[typeIndex];
                    }
                    return true;
                default:
                    value = null;
                    return false;
            }
        }

        public Il2CppTypeEnum ReadEncodedTypeEnum(BinaryReader reader, out Il2CppType enumType)
        {
            enumType = null;
            var type = (Il2CppTypeEnum)reader.ReadByte();
            if (type == Il2CppTypeEnum.IL2CPP_TYPE_ENUM)
            {
                var enumTypeIndex = reader.ReadCompressedInt32();
                enumType = il2Cpp.types[enumTypeIndex];
                var typeDef = GetTypeDefinitionFromIl2CppType(enumType);
                type = il2Cpp.types[typeDef.GetEnumElementTypeIndex(il2Cpp.Version)].type;
            }
            return type;
        }
    }
}
