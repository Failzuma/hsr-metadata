using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using static Il2CppDumper.Il2CppConstants;

namespace Il2CppDumper
{
    public class Il2CppDecompiler
    {
        private readonly Il2CppExecutor executor;
        private readonly Metadata metadata;
        private readonly Il2Cpp il2Cpp;
        private readonly Dictionary<Il2CppMethodDefinition, string> methodModifiers;
        private static readonly IReadOnlyDictionary<string, string> TypeAliases = new Dictionary<string, string>
        {
            ["System.Boolean"] = "bool",
            ["System.Byte"] = "byte",
            ["System.Char"] = "char",
            ["System.Double"] = "double",
            ["System.Int16"] = "short",
            ["System.Int32"] = "int",
            ["System.Int64"] = "long",
            ["System.Object"] = "object",
            ["System.SByte"] = "sbyte",
            ["System.Single"] = "float",
            ["System.String"] = "string",
            ["System.UInt16"] = "ushort",
            ["System.UInt32"] = "uint",
            ["System.UInt64"] = "ulong",
            ["System.Void"] = "void"
        };

        public Il2CppDecompiler(Il2CppExecutor il2CppExecutor)
        {
            executor = il2CppExecutor;
            metadata = il2CppExecutor.metadata;
            il2Cpp = il2CppExecutor.il2Cpp;
            methodModifiers = new();
        }

        private static string GetMethodDisplayName(string rawName)
        {
            var separator = rawName.LastIndexOf('.');
            if (separator < 0)
                return rawName;

            var memberName = rawName[(separator + 1)..];
            var qualification = rawName[..separator];
            if (!qualification.Contains('<'))
                return memberName;

            foreach (var alias in TypeAliases)
                qualification = qualification.Replace(alias.Key, alias.Value);
            qualification = Regex.Replace(qualification, @"(?:[A-Za-z_][A-Za-z0-9_]*\.)+([A-Za-z_][A-Za-z0-9_]*)", "$1");
            qualification = Regex.Replace(qualification, @",\s*", ", ");
            return qualification + memberName;
        }

        public void Decompile(Config config, string outputDir)
        {
            var writer = new StreamWriter(new FileStream(outputDir + "dump.cs", FileMode.Create), new UTF8Encoding(false));
            //dump image
            for (var imageIndex = 0; imageIndex < metadata.imageDefs.Length; imageIndex++)
            {
                var imageDef = metadata.imageDefs[imageIndex];
                writer.Write($"// Image {imageIndex}: {metadata.GetStringFromIndex(imageDef.nameIndex)}\n");
            }
            //dump type
            foreach (var imageDef in metadata.imageDefs)
            {
                try
                {
                    var imageName = metadata.GetStringFromIndex(imageDef.nameIndex);
                    var typeEnd = imageDef.typeStart + imageDef.typeCount;
                    for (int typeDefIndex = imageDef.typeStart; typeDefIndex < typeEnd; typeDefIndex++)
                    {
                        var typeDef = metadata.typeDefs[typeDefIndex];
                        var isValueType = typeDef.IsValueType;
                        var isEnum = typeDef.IsEnum;
                        var ns = metadata.GetStringFromIndex(typeDef.namespaceIndex);
                        var declaredName = metadata.GetStringFromIndex(typeDef.nameIndex);
                        var isSystemEnum = ns == "System" && declaredName == "Enum";
                        if (!isSystemEnum && !isValueType && !isEnum && typeDef.parentIndex >= 0 && typeDef.parentIndex < il2Cpp.types.Length)
                        {
                            try
                            {
                                var parent = il2Cpp.types[typeDef.parentIndex];
                                if (parent != null)
                                {
                                    var parentName = executor.GetTypeName(parent, false, false);
                                    if (parentName == "ValueType" || parentName == "System.ValueType")
                                    {
                                        isValueType = true;
                                    }
                                    else if (parentName == "Enum" || parentName == "System.Enum")
                                    {
                                        isEnum = true;
                                    }
                                }
                            }
                            catch { }
                        }

                        var extends = new List<string>();
                        if (typeDef.parentIndex >= 0 && typeDef.parentIndex < il2Cpp.types.Length)
                        {
                            try
                            {
                                var parent = il2Cpp.types[typeDef.parentIndex];
                                if (parent != null)
                                {
                                    var parentName = executor.GetTypeName(parent, false, false);
                                    if (!isValueType && !isEnum && (parentName != "object" || typeDef.interfaces_count > 0))
                                    {
                                        extends.Add(parentName == "object" ? "Object" : parentName);
                                    }
                                }
                            }
                            catch { }
                        }
                        if (typeDef.interfaces_count > 0 && metadata.interfaceIndices != null)
                        {
                            for (int i = 0; i < typeDef.interfaces_count; i++)
                            {
                                int idx = typeDef.interfacesStart + i;
                                if (idx >= 0 && idx < metadata.interfaceIndices.Length)
                                {
                                    var interfaceTypeIndex = metadata.interfaceIndices[idx];
                                    if (interfaceTypeIndex >= 0)
                                    {
                                        var ifName = executor.GetTypeNameFromIndex(interfaceTypeIndex, false);
                                        if (!string.IsNullOrEmpty(ifName) && ifName != "object")
                                        {
                                            extends.Add(ifName);
                                        }
                                    }
                                }
                            }
                        }
                        writer.Write($"\n// Module: {imageName}\n");
                        if (!string.IsNullOrEmpty(ns))
                        {
                            writer.Write($"// Namespace: {ns}\n");
                        }
                        if (typeDef.declaringTypeIndex >= 0)
                        {
                            writer.Write($"// Declaring Type: {executor.GetTypeNameFromIndex(typeDef.declaringTypeIndex, false)}\n");
                        }
                        if (config.DumpAttribute)
                        {
                            writer.Write(GetCustomAttribute(imageDef, typeDef.customAttributeIndex, typeDef.token));
                        }
                        var visibility = typeDef.flags & TYPE_ATTRIBUTE_VISIBILITY_MASK;
                        switch (visibility)
                        {
                            case TYPE_ATTRIBUTE_PUBLIC:
                            case TYPE_ATTRIBUTE_NESTED_PUBLIC:
                                writer.Write("public ");
                                break;
                            case TYPE_ATTRIBUTE_NOT_PUBLIC:
                            case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:
                            case TYPE_ATTRIBUTE_NESTED_ASSEMBLY:
                                writer.Write("internal ");
                                break;
                            case TYPE_ATTRIBUTE_NESTED_PRIVATE:
                                writer.Write("private ");
                                break;
                            case TYPE_ATTRIBUTE_NESTED_FAMILY:
                                writer.Write("protected ");
                                break;
                            case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM:
                                writer.Write("protected internal ");
                                break;
                        }
                        var isInterface = (typeDef.flags & TYPE_ATTRIBUTE_INTERFACE) != 0 && !isValueType && !isEnum && typeDef.parentIndex == -1;
                        if ((typeDef.flags & TYPE_ATTRIBUTE_ABSTRACT) != 0 && (typeDef.flags & TYPE_ATTRIBUTE_SEALED) != 0 && !isValueType && !isEnum)
                            writer.Write("static ");
                        else if (!isInterface && (typeDef.flags & TYPE_ATTRIBUTE_ABSTRACT) != 0 && !isValueType && !isEnum)
                            writer.Write("abstract ");
                        else if (!isValueType && !isEnum && (typeDef.flags & TYPE_ATTRIBUTE_SEALED) != 0)
                            writer.Write("sealed ");
                        if (isInterface)
                            writer.Write("interface ");
                        else if (isEnum)
                            writer.Write("enum ");
                        else if (isValueType)
                            writer.Write("struct ");
                        else
                            writer.Write("class ");
                        var typeName = executor.GetTypeDefName(typeDef, false, true, false);
                        writer.Write($"{typeName}");
                        if (extends.Count > 0)
                            writer.Write($" : {string.Join(", ", extends)}");
                        if (config.DumpTypeDefIndex)
                            writer.Write($" // TypeDefIndex: {typeDefIndex}\n{{");
                        else
                            writer.Write("\n{");
                        //dump field
                        if (config.DumpField && typeDef.field_count > 0)
                        {
                            writer.Write("\n\t// Fields\n");
                            var fieldEnd = typeDef.fieldStart + typeDef.field_count;
                            for (var i = typeDef.fieldStart; i < fieldEnd; ++i)
                            {
                                if (i < 0 || i >= metadata.fieldDefs.Length)
                                    continue;
                                var isConst = false;
                                var isStatic = false;
                                var fieldDef = metadata.fieldDefs[i];
                                var fieldType = (fieldDef.typeIndex >= 0 && fieldDef.typeIndex < il2Cpp.types.Length) ? il2Cpp.types[fieldDef.typeIndex] : null;
                                if (fieldType == null)
                                    continue;
                                if (config.DumpAttribute)
                                {
                                    writer.Write(GetCustomAttribute(imageDef, fieldDef.customAttributeIndex, fieldDef.token, "\t"));
                                }
                                writer.Write("\t");
                                var access = fieldType.attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK;
                                switch (access)
                                {
                                    case FIELD_ATTRIBUTE_PRIVATE:
                                        writer.Write("private ");
                                        break;
                                    case FIELD_ATTRIBUTE_PUBLIC:
                                        writer.Write("public ");
                                        break;
                                    case FIELD_ATTRIBUTE_FAMILY:
                                        writer.Write("protected ");
                                        break;
                                    case FIELD_ATTRIBUTE_ASSEMBLY:
                                    case FIELD_ATTRIBUTE_FAM_AND_ASSEM:
                                        writer.Write("internal ");
                                        break;
                                    case FIELD_ATTRIBUTE_FAM_OR_ASSEM:
                                        writer.Write("protected internal ");
                                        break;
                                }
                                if ((fieldType.attrs & FIELD_ATTRIBUTE_LITERAL) != 0)
                                {
                                    isConst = true;
                                    writer.Write("const ");
                                }
                                else
                                {
                                    if ((fieldType.attrs & FIELD_ATTRIBUTE_STATIC) != 0)
                                    {
                                        isStatic = true;
                                        writer.Write("static ");
                                    }
                                    if ((fieldType.attrs & FIELD_ATTRIBUTE_INIT_ONLY) != 0)
                                    {
                                        writer.Write("readonly ");
                                    }
                                }
                                var fieldTypeName = executor.GetTypeNameFromIndex(fieldDef.typeIndex, false);
                                writer.Write($"{fieldTypeName} {metadata.GetStringFromIndex(fieldDef.nameIndex)}");
                                if (metadata.GetFieldDefaultValueFromIndex(i, out var fieldDefaultValue) && fieldDefaultValue.dataIndex != -1)
                                {
                                    if (executor.TryGetDefaultValue(fieldDefaultValue.typeIndex, fieldDefaultValue.dataIndex, out var value))
                                    {
                                        writer.Write($" = ");
                                        if (value is string str)
                                        {
                                            writer.Write($"\"{str.ToEscapedString()}\"");
                                        }
                                        else if (value is char c)
                                        {
                                            var v = (int)c;
                                            writer.Write($"'\\x{v:x}'");
                                        }
                                        else if (value != null)
                                        {
                                            writer.Write($"{value}");
                                        }
                                        else
                                        {
                                            writer.Write("null");
                                        }
                                    }
                                    else
                                    {
                                        writer.Write($" /*Metadata offset 0x{value:X}*/");
                                    }
                                }
                                if (config.DumpFieldOffset && !isConst)
                                    writer.Write("; // 0x{0:X}\n", il2Cpp.GetFieldOffsetFromIndex(typeDefIndex, i - typeDef.fieldStart, i, typeDef.IsValueType, isStatic));
                                else
                                    writer.Write(";\n");
                            }
                        }
                        //dump property
                        if (config.DumpProperty && typeDef.property_count > 0)
                        {
                            writer.Write("\n\t// Properties\n");
                            var propertyEnd = typeDef.propertyStart + typeDef.property_count;
                            for (var i = typeDef.propertyStart; i < propertyEnd; ++i)
                            {
                                if (i < 0 || i >= metadata.propertyDefs.Length)
                                    continue;
                                var propertyDef = metadata.propertyDefs[i];
                                if (config.DumpAttribute)
                                {
                                    writer.Write(GetCustomAttribute(imageDef, propertyDef.customAttributeIndex, propertyDef.token, "\t"));
                                }
                                writer.Write("\t");
                                if (propertyDef.get >= 0 && typeDef.methodStart + propertyDef.get < metadata.methodDefs.Length)
                                {
                                    var methodDef = metadata.methodDefs[typeDef.methodStart + propertyDef.get];
                                    writer.Write(GetModifiers(methodDef));
                                    var propertyType = (methodDef.returnType >= 0 && methodDef.returnType < il2Cpp.types.Length) ? il2Cpp.types[methodDef.returnType] : null;
                                    writer.Write($"{executor.GetTypeName(propertyType, false, false)} {metadata.GetStringFromIndex(propertyDef.nameIndex)} {{ ");
                                }
                                else if (propertyDef.set >= 0 && typeDef.methodStart + propertyDef.set < metadata.methodDefs.Length)
                                {
                                    var methodDef = metadata.methodDefs[typeDef.methodStart + propertyDef.set];
                                    writer.Write(GetModifiers(methodDef));
                                    if (methodDef.parameterStart < metadata.parameterDefs.Length)
                                    {
                                        var parameterDef = metadata.parameterDefs[methodDef.parameterStart];
                                        var propertyType = (parameterDef.typeIndex >= 0 && parameterDef.typeIndex < il2Cpp.types.Length) ? il2Cpp.types[parameterDef.typeIndex] : null;
                                        writer.Write($"{executor.GetTypeName(propertyType, false, false)} {metadata.GetStringFromIndex(propertyDef.nameIndex)} {{ ");
                                    }
                                }
                                if (propertyDef.get >= 0)
                                    writer.Write("get; ");
                                if (propertyDef.set >= 0)
                                    writer.Write("set; ");
                                writer.Write("}");
                                writer.Write("\n");
                            }
                        }
                        //dump method
                        if (config.DumpMethod && typeDef.method_count > 0)
                        {
                            writer.Write("\n\t// Methods\n");
                            var methodEnd = typeDef.methodStart + typeDef.method_count;
                            for (var i = typeDef.methodStart; i < methodEnd; ++i)
                            {
                                if (i < 0 || i >= metadata.methodDefs.Length)
                                    continue;
                                writer.Write("\n");
                                var methodDef = metadata.methodDefs[i];
                                var isAbstract = (methodDef.flags & METHOD_ATTRIBUTE_ABSTRACT) != 0;
                                if (config.DumpAttribute)
                                {
                                    writer.Write(GetCustomAttribute(imageDef, methodDef.customAttributeIndex, methodDef.token, "\t"));
                                }
                                if (config.DumpMethodOffset)
                                {
                                    var methodPointer = il2Cpp.GetMethodPointer(imageName, methodDef);
                                    if (methodPointer > 0)
                                    {
                                        var fixedMethodPointer = il2Cpp.GetRVA(methodPointer);
                                        writer.Write("\t// RVA: 0x{0:X} Offset: 0x{1:X} VA: 0x{2:X}", fixedMethodPointer, il2Cpp.MapVATR(methodPointer), methodPointer);
                                    }
                                    else
                                    {
                                        writer.Write("\t// RVA: -1 Offset: -1");
                                    }
                                    if (methodDef.slot != ushort.MaxValue)
                                    {
                                        writer.Write(" Slot: {0}", methodDef.slot);
                                    }
                                    writer.Write("\n");
                                }
                                writer.Write("\t");
                                writer.Write(GetModifiers(methodDef));
                                var methodReturnType = (methodDef.returnType >= 0 && methodDef.returnType < il2Cpp.types.Length) ? il2Cpp.types[methodDef.returnType] : null;
                                var methodName = GetMethodDisplayName(metadata.GetStringFromIndex(methodDef.nameIndex));
                                if (methodDef.genericContainerIndex >= 0 && metadata.genericContainers != null && methodDef.genericContainerIndex < metadata.genericContainers.Length)
                                {
                                    var genericContainer = metadata.genericContainers[methodDef.genericContainerIndex];
                                    methodName += executor.GetGenericContainerParams(genericContainer);
                                }
                                if (methodName == "ctor" || methodName == "cctor")
                                {
                                    writer.Write($"void {methodName}(");
                                }
                                else
                                {
                                    if (methodReturnType != null && methodReturnType.byref == 1)
                                    {
                                        writer.Write("ref ");
                                    }
                                    var retTypeName = executor.GetTypeNameFromIndex(methodDef.returnType, false);
                                    writer.Write($"{retTypeName} {methodName}(");
                                }
                                var parameterStrs = new List<string>();
                                for (int j = 0; j < methodDef.parameterCount; ++j)
                                {
                                    if (metadata.parameterDefs == null || methodDef.parameterStart + j < 0 || methodDef.parameterStart + j >= metadata.parameterDefs.Length)
                                        continue;
                                    var parameterStr = "";

                                    var parameterDef = metadata.parameterDefs[methodDef.parameterStart + j];
                                    var parameterName = metadata.GetStringFromIndex(parameterDef.nameIndex);
                                    if (string.IsNullOrEmpty(parameterName))
                                        parameterName = $"a{j + 1}";
                                    var parameterType = (parameterDef.typeIndex >= 0 && parameterDef.typeIndex < il2Cpp.types.Length) ? il2Cpp.types[parameterDef.typeIndex] : null;
                                    var parameterTypeName = executor.GetTypeNameFromIndex(parameterDef.typeIndex, false);
                                    if (parameterType != null && parameterType.byref == 1)
                                    {
                                        if ((parameterType.attrs & PARAM_ATTRIBUTE_OUT) != 0 && (parameterType.attrs & PARAM_ATTRIBUTE_IN) == 0)
                                        {
                                            parameterStr += "out ";
                                        }
                                        else if ((parameterType.attrs & PARAM_ATTRIBUTE_OUT) == 0 && (parameterType.attrs & PARAM_ATTRIBUTE_IN) != 0)
                                        {
                                            parameterStr += "in ";
                                        }
                                        else
                                        {
                                            parameterStr += "ref ";
                                        }
                                    }
                                    else if (parameterType != null)
                                    {
                                        if ((parameterType.attrs & PARAM_ATTRIBUTE_IN) != 0)
                                        {
                                            parameterStr += "[In] ";
                                        }
                                        if ((parameterType.attrs & PARAM_ATTRIBUTE_OUT) != 0)
                                        {
                                            parameterStr += "[Out] ";
                                        }
                                    }
                                    parameterStr += $"{parameterTypeName} {parameterName}";
                                    if (metadata.GetParameterDefaultValueFromIndex(methodDef.parameterStart + j, out var parameterDefault) && parameterDefault.dataIndex != -1)
                                    {
                                        if (executor.TryGetDefaultValue(parameterDefault.typeIndex, parameterDefault.dataIndex, out var value))
                                        {
                                            parameterStr += " = ";
                                            if (value is string str)
                                            {
                                                parameterStr += $"\"{str.ToEscapedString()}\"";
                                            }
                                            else if (value is char c)
                                            {
                                                var v = (int)c;
                                                parameterStr += $"'\\x{v:x}'";
                                            }
                                            else if (value != null)
                                            {
                                                parameterStr += $"{value}";
                                            }
                                            else
                                            {
                                                writer.Write("null");
                                            }
                                        }
                                        else
                                        {
                                            parameterStr += $" /*Metadata offset 0x{value:X}*/";
                                        }
                                    }
                                    parameterStrs.Add(parameterStr);
                                }
                                writer.Write(string.Join(", ", parameterStrs));
                                if (isAbstract)
                                {
                                    writer.Write(");\n");
                                }
                                else
                                {
                                    writer.Write(") { }\n");
                                }

                                if (il2Cpp.methodDefinitionMethodSpecs.TryGetValue(i, out var methodSpecs))
                                {
                                    writer.Write("\t/* GenericInstMethod :\n");
                                    var groups = methodSpecs.GroupBy(x => il2Cpp.methodSpecGenericMethodPointers[x]);
                                    foreach (var group in groups)
                                    {
                                        writer.Write("\t|\n");
                                        var genericMethodPointer = group.Key;
                                        if (genericMethodPointer > 0)
                                        {
                                            var fixedPointer = il2Cpp.GetRVA(genericMethodPointer);
                                            writer.Write($"\t|-RVA: 0x{fixedPointer:X} Offset: 0x{il2Cpp.MapVATR(genericMethodPointer):X} VA: 0x{genericMethodPointer:X}\n");
                                        }
                                        else
                                        {
                                            writer.Write("\t|-RVA: -1 Offset: -1\n");
                                        }
                                        foreach (var methodSpec in group)
                                        {
                                            (var methodSpecTypeName, var methodSpecMethodName) = executor.GetMethodSpecName(methodSpec);
                                            writer.Write($"\t|-{methodSpecTypeName}.{methodSpecMethodName}\n");
                                        }
                                    }
                                    writer.Write("\t*/\n");
                                }
                            }
                        }
                        writer.Write("}\n");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("ERROR in image " + metadata.GetStringFromIndex(imageDef.nameIndex) + ": " + ex.Message);
                    writer.Write("/*");
                    writer.Write(ex);
                    writer.Write("*/\n}\n");
                }
            }
            writer.Close();
        }

        public string GetCustomAttribute(Il2CppImageDefinition imageDef, int customAttributeIndex, uint token, string padding = "")
        {
            if (il2Cpp.Version < 21)
                return string.Empty;
            var attributeIndex = metadata.GetCustomAttributeIndex(imageDef, customAttributeIndex, token);
            if (attributeIndex >= 0)
            {
                if (il2Cpp.Version < 29)
                {
                    var methodPointer = executor.customAttributeGenerators[attributeIndex];
                    var fixedMethodPointer = il2Cpp.GetRVA(methodPointer);
                    var attributeTypeRange = metadata.attributeTypeRanges[attributeIndex];
                    var sb = new StringBuilder();
                    for (var i = 0; i < attributeTypeRange.count; i++)
                    {
                        var typeIndex = metadata.attributeTypes[attributeTypeRange.start + i];
                        sb.AppendFormat("{0}[{1}] // RVA: 0x{2:X} Offset: 0x{3:X} VA: 0x{4:X}\n",
                            padding,
                            executor.GetTypeName(il2Cpp.types[typeIndex], false, false),
                            fixedMethodPointer,
                            il2Cpp.MapVATR(methodPointer),
                            methodPointer);
                    }
                    return sb.ToString();
                }
                else
                {
                    var startRange = metadata.attributeDataRanges[attributeIndex];
                    var endRange = metadata.attributeDataRanges[attributeIndex + 1];
                    metadata.Position = (il2Cpp.Version < 38 ? metadata.header.attributeDataOffset : metadata.header.attributeData.offset) + startRange.startOffset;
                    var buff = metadata.ReadBytes((int)(endRange.startOffset - startRange.startOffset));
                    var reader = new CustomAttributeDataReader(executor, buff);
                    if (reader.Count == 0)
                    {
                        return string.Empty;
                    }
                    var sb = new StringBuilder();
                    for (var i = 0; i < reader.Count; i++)
                    {
                        sb.Append(padding);
                        sb.Append(reader.GetStringCustomAttributeData());
                        sb.Append('\n');
                    }
                    return sb.ToString();
                }
            }
            else
            {
                return string.Empty;
            }
        }

        public string GetModifiers(Il2CppMethodDefinition methodDef)
        {
            if (methodModifiers.TryGetValue(methodDef, out string str))
                return str;
            var access = methodDef.flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK;
            switch (access)
            {
                case METHOD_ATTRIBUTE_PRIVATE:
                    str += "private ";
                    break;
                case METHOD_ATTRIBUTE_PUBLIC:
                    str += "public ";
                    break;
                case METHOD_ATTRIBUTE_FAMILY:
                    str += "protected ";
                    break;
                case METHOD_ATTRIBUTE_ASSEM:
                case METHOD_ATTRIBUTE_FAM_AND_ASSEM:
                    str += "internal ";
                    break;
                case METHOD_ATTRIBUTE_FAM_OR_ASSEM:
                    str += "protected internal ";
                    break;
            }
            if ((methodDef.flags & METHOD_ATTRIBUTE_STATIC) != 0)
                str += "static ";
            if ((methodDef.flags & METHOD_ATTRIBUTE_ABSTRACT) != 0)
            {
                str += "abstract ";
                if ((methodDef.flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT)
                    str += "override ";
            }
            else if ((methodDef.flags & METHOD_ATTRIBUTE_FINAL) != 0)
            {
                if ((methodDef.flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT)
                    str += "sealed override ";
                else if ((methodDef.flags & METHOD_ATTRIBUTE_VIRTUAL) != 0)
                    str += "virtual ";
            }
            else if ((methodDef.flags & METHOD_ATTRIBUTE_VIRTUAL) != 0)
            {
                if ((methodDef.flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_NEW_SLOT)
                    str += "virtual ";
                else
                    str += "override ";
            }
            if ((methodDef.flags & METHOD_ATTRIBUTE_PINVOKE_IMPL) != 0)
                str += "extern ";
            methodModifiers.Add(methodDef, str);
            return str;
        }
    }
}
