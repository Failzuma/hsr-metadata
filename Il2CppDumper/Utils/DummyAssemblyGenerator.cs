using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Collections.Generic;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Il2CppDumper
{
    public class DummyAssemblyGenerator
    {
        public List<AssemblyDefinition> Assemblies = new();

        private readonly Il2CppExecutor executor;
        private readonly Metadata metadata;
        private readonly Il2Cpp il2Cpp;
        private readonly Dictionary<Il2CppTypeDefinition, TypeDefinition> typeDefinitionDic = new();
        private readonly Dictionary<Il2CppGenericParameter, GenericParameter> genericParameterDic = new();
        private readonly MethodDefinition attributeAttribute;
        private readonly TypeReference stringType;
        private readonly TypeSystem typeSystem;
        private readonly Dictionary<int, FieldDefinition> fieldDefinitionDic = new();
        private readonly Dictionary<int, PropertyDefinition> propertyDefinitionDic = new();
        private readonly Dictionary<int, MethodDefinition> methodDefinitionDic = new();

        public DummyAssemblyGenerator(Il2CppExecutor il2CppExecutor, bool addToken)
        {
            executor = il2CppExecutor;
            metadata = il2CppExecutor.metadata;
            il2Cpp = il2CppExecutor.il2Cpp;

            //Il2CppDummyDll
            var il2CppDummyDll = AssemblyDefinition.ReadAssembly(new MemoryStream(Resource1.Il2CppDummyDll));
            Assemblies.Add(il2CppDummyDll);
            var dummyMD = il2CppDummyDll.MainModule;
            var addressAttribute = dummyMD.Types.First(x => x.Name == "AddressAttribute").Methods[0];
            var fieldOffsetAttribute = dummyMD.Types.First(x => x.Name == "FieldOffsetAttribute").Methods[0];
            attributeAttribute = dummyMD.Types.First(x => x.Name == "AttributeAttribute").Methods[0];
            var metadataOffsetAttribute = dummyMD.Types.First(x => x.Name == "MetadataOffsetAttribute").Methods[0];
            var tokenAttribute = dummyMD.Types.First(x => x.Name == "TokenAttribute").Methods[0];
            stringType = dummyMD.TypeSystem.String;
            typeSystem = dummyMD.TypeSystem;

            var resolver = new MyAssemblyResolver();
            var moduleParameters = new ModuleParameters
            {
                Kind = ModuleKind.Dll,
                AssemblyResolver = resolver
            };
            resolver.Register(il2CppDummyDll);

            var parameterDefinitionDic = new Dictionary<int, ParameterDefinition>();
            var eventDefinitionDic = new Dictionary<int, EventDefinition>();

            //创建程序集，同时创建所有类
            foreach (var imageDef in metadata.imageDefs)
            {
                var imageName = metadata.GetStringFromIndex(imageDef.nameIndex);
                string assemblyName = "";
                if (imageDef.assemblyIndex >= 0 && metadata.assemblyDefs != null && imageDef.assemblyIndex < metadata.assemblyDefs.Length)
                {
                    var aname = metadata.assemblyDefs[imageDef.assemblyIndex].aname;
                    assemblyName = metadata.GetStringFromIndex(aname.nameIndex);
                }
                if (string.IsNullOrEmpty(assemblyName))
                {
                    assemblyName = !string.IsNullOrEmpty(imageName) ? Path.GetFileNameWithoutExtension(imageName) : $"Assembly_{imageDef.assemblyIndex}";
                }
                else
                {
                    assemblyName = Path.GetFileNameWithoutExtension(assemblyName);
                }
                if (string.IsNullOrEmpty(imageName))
                {
                    imageName = assemblyName + ".dll";
                }
                Version vers = new Version();
                var assemblyNameDef = new AssemblyNameDefinition(assemblyName, vers);
                var assemblyDefinition = AssemblyDefinition.CreateAssembly(assemblyNameDef, imageName, moduleParameters);
                resolver.Register(assemblyDefinition);
                Assemblies.Add(assemblyDefinition);
                var moduleDefinition = assemblyDefinition.MainModule;
                moduleDefinition.Types.Clear();//清除自动创建的<Module>类
                var typeEnd = imageDef.typeStart + imageDef.typeCount;
                for (int index = imageDef.typeStart; index < typeEnd; ++index)
                {
                    var typeDef = metadata.typeDefs[index];
                    var namespaceName = metadata.GetStringFromIndex(typeDef.namespaceIndex);
                    var typeName = metadata.GetStringFromIndex(typeDef.nameIndex);

                    var isValueType = typeDef.IsValueType;
                    var isEnum = typeDef.IsEnum;
                    if (!isValueType && !isEnum && typeDef.parentIndex >= 0 && typeDef.parentIndex < il2Cpp.types.Length)
                    {
                        try
                        {
                            var parentType = il2Cpp.types[typeDef.parentIndex];
                            if (parentType != null)
                            {
                                var pName = executor.GetTypeName(parentType, false, false);
                                if (pName == "ValueType" || pName == "System.ValueType")
                                    isValueType = true;
                                else if (pName == "Enum" || pName == "System.Enum")
                                    isEnum = true;
                        }
                        }
                        catch { }
                    }

                    var attrs = (TypeAttributes)typeDef.flags;
                    if (isValueType)
                    {
                        attrs = (attrs & ~TypeAttributes.Interface & ~TypeAttributes.Abstract) | TypeAttributes.SequentialLayout | TypeAttributes.Sealed;
                    }
                    else if (isEnum)
                    {
                        attrs = (attrs & ~TypeAttributes.Interface & ~TypeAttributes.Abstract) | TypeAttributes.Sealed;
                    }
                    else if ((attrs & TypeAttributes.Interface) != 0 && typeDef.parentIndex == -1)
                    {
                        attrs = (attrs & ~TypeAttributes.Sealed) | TypeAttributes.Interface | TypeAttributes.Abstract;
                    }
                    else
                    {
                        attrs = attrs & ~TypeAttributes.Interface;
                    }

                    var typeDefinition = new TypeDefinition(namespaceName, typeName, attrs);
                    typeDefinitionDic[typeDef] = typeDefinition;
                    if (typeDef.declaringTypeIndex == -1)
                    {
                        moduleDefinition.Types.Add(typeDefinition);
                    }
                }
            }
            foreach (var imageDef in metadata.imageDefs)
            {
                var typeEnd = imageDef.typeStart + imageDef.typeCount;
                for (int index = imageDef.typeStart; index < typeEnd; ++index)
                {
                    var typeDef = metadata.typeDefs[index];
                    if (!typeDefinitionDic.TryGetValue(typeDef, out var typeDefinition))
                        continue;

                    //nestedtype
                    for (int i = 0; i < typeDef.nested_type_count; i++)
                    {
                        if (typeDef.nestedTypesStart + i < metadata.nestedTypeIndices.Length)
                        {
                            var nestedIndex = metadata.nestedTypeIndices[typeDef.nestedTypesStart + i];
                            if (nestedIndex >= 0 && nestedIndex < metadata.typeDefs.Length)
                            {
                                var nestedTypeDef = metadata.typeDefs[nestedIndex];
                                if (typeDefinitionDic.TryGetValue(nestedTypeDef, out var nestedTypeDefinition))
                                {
                                    typeDefinition.NestedTypes.Add(nestedTypeDefinition);
                                }
                            }
                        }
                    }
                }
            }
            //提前处理
            foreach (var imageDef in metadata.imageDefs)
            {
                var typeEnd = imageDef.typeStart + imageDef.typeCount;
                for (int index = imageDef.typeStart; index < typeEnd; ++index)
                {
                    if (index < 0 || index >= metadata.typeDefs.Length)
                        continue;
                    var typeDef = metadata.typeDefs[index];
                    if (!typeDefinitionDic.TryGetValue(typeDef, out var typeDefinition) || typeDefinition == null)
                        continue;

                    if (addToken && typeDefinition.Module != null)
                    {
                        var customTokenAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(tokenAttribute));
                        customTokenAttribute.Fields.Add(new CustomAttributeNamedArgument("Token", new CustomAttributeArgument(stringType, $"0x{typeDef.token:X}")));
                        typeDefinition.CustomAttributes.Add(customTokenAttribute);
                    }

                    //genericParameter
                    if (typeDef.genericContainerIndex >= 0 && metadata.genericContainers != null && typeDef.genericContainerIndex < metadata.genericContainers.Length)
                    {
                        var genericContainer = metadata.genericContainers[typeDef.genericContainerIndex];
                        for (int i = 0; i < genericContainer.type_argc; i++)
                        {
                            var genericParameterIndex = genericContainer.genericParameterStart + i;
                            if (metadata.genericParameters != null && genericParameterIndex >= 0 && genericParameterIndex < metadata.genericParameters.Length)
                            {
                                var param = metadata.genericParameters[genericParameterIndex];
                                var genericParameter = CreateGenericParameter(param, typeDefinition);
                                typeDefinition.GenericParameters.Add(genericParameter);
                            }
                        }
                    }

                    //parent
                    if (typeDef.parentIndex >= 0 && typeDef.parentIndex < il2Cpp.types.Length)
                    {
                        var parentType = il2Cpp.types[typeDef.parentIndex];
                        if (parentType != null)
                        {
                            var parentTypeRef = GetTypeReference(typeDefinition, parentType);
                            typeDefinition.BaseType = parentTypeRef;
                        }
                    }

                    //interfaces
                    if (metadata.interfaceIndices != null && typeDef.interfaces_count > 0)
                    {
                        for (int i = 0; i < typeDef.interfaces_count; i++)
                        {
                            int idx = typeDef.interfacesStart + i;
                            if (idx >= 0 && idx < metadata.interfaceIndices.Length)
                            {
                                var interfaceTypeIndex = metadata.interfaceIndices[idx];
                                if (interfaceTypeIndex >= 0 && interfaceTypeIndex < il2Cpp.types.Length)
                                {
                                    var interfaceType = il2Cpp.types[interfaceTypeIndex];
                                    if (interfaceType != null)
                                    {
                                        var interfaceTypeRef = GetTypeReference(typeDefinition, interfaceType);
                                        typeDefinition.Interfaces.Add(new InterfaceImplementation(interfaceTypeRef));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            //处理field, method, property等等
            foreach (var imageDef in metadata.imageDefs)
            {
                var imageName = metadata.GetStringFromIndex(imageDef.nameIndex);
                var typeEnd = imageDef.typeStart + imageDef.typeCount;
                for (int index = imageDef.typeStart; index < typeEnd; index++)
                {
                    if (index < 0 || index >= metadata.typeDefs.Length)
                        continue;
                    var typeDef = metadata.typeDefs[index];
                    if (!typeDefinitionDic.TryGetValue(typeDef, out var typeDefinition) || typeDefinition == null)
                        continue;

                    //field
                    var fieldEnd = typeDef.fieldStart + typeDef.field_count;
                    for (var i = typeDef.fieldStart; i < fieldEnd; ++i)
                    {
                        if (i < 0 || i >= metadata.fieldDefs.Length)
                            continue;
                        var fieldDef = metadata.fieldDefs[i];
                        var fieldType = (fieldDef.typeIndex >= 0 && fieldDef.typeIndex < il2Cpp.types.Length) ? il2Cpp.types[fieldDef.typeIndex] : null;
                        var fieldName = metadata.GetStringFromIndex(fieldDef.nameIndex);
                        if (string.IsNullOrEmpty(fieldName)) fieldName = $"field_{i}";
                        var fieldTypeRef = GetTypeReference(typeDefinition, fieldType);
                        var fieldDefinition = new FieldDefinition(fieldName, (FieldAttributes)(fieldType?.attrs ?? 0), fieldTypeRef);
                        typeDefinition.Fields.Add(fieldDefinition);
                        fieldDefinitionDic[i] = fieldDefinition;

                        if (addToken && typeDefinition.Module != null)
                        {
                            var customTokenAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(tokenAttribute));
                            customTokenAttribute.Fields.Add(new CustomAttributeNamedArgument("Token", new CustomAttributeArgument(stringType, $"0x{fieldDef.token:X}")));
                            fieldDefinition.CustomAttributes.Add(customTokenAttribute);
                        }

                        //fieldDefault
                        if (metadata.GetFieldDefaultValueFromIndex(i, out var fieldDefault) && fieldDefault.dataIndex != -1)
                        {
                            if (executor.TryGetDefaultValue(fieldDefault.typeIndex, fieldDefault.dataIndex, out var value))
                            {
                                fieldDefinition.Constant = value;
                            }
                            else if (typeDefinition.Module != null)
                            {
                                var customAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(metadataOffsetAttribute));
                                var offset = new CustomAttributeNamedArgument("Offset", new CustomAttributeArgument(stringType, $"0x{value:X}"));
                                customAttribute.Fields.Add(offset);
                                fieldDefinition.CustomAttributes.Add(customAttribute);
                            }
                        }
                        //fieldOffset
                        if (!fieldDefinition.IsLiteral && typeDefinition.Module != null)
                        {
                            var fieldOffset = il2Cpp.GetFieldOffsetFromIndex(index, i - typeDef.fieldStart, i, typeDefinition.IsValueType, fieldDefinition.IsStatic);
                            if (fieldOffset >= 0)
                            {
                                var customAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(fieldOffsetAttribute));
                                var offset = new CustomAttributeNamedArgument("Offset", new CustomAttributeArgument(stringType, $"0x{fieldOffset:X}"));
                                customAttribute.Fields.Add(offset);
                                fieldDefinition.CustomAttributes.Add(customAttribute);
                            }
                        }
                    }
                    //method
                    var methodEnd = typeDef.methodStart + typeDef.method_count;
                    for (var i = typeDef.methodStart; i < methodEnd; ++i)
                    {
                        if (i < 0 || i >= metadata.methodDefs.Length)
                            continue;
                        var methodDef = metadata.methodDefs[i];
                        var methodName = metadata.GetStringFromIndex(methodDef.nameIndex);
                        if (string.IsNullOrEmpty(methodName)) methodName = $"Method_{i}";
                        var mod = typeDefinition.Module ?? typeSystem.Object.Module;
                        var methodDefinition = new MethodDefinition(methodName, (MethodAttributes)methodDef.flags, mod.ImportReference(typeSystem.Void))
                        {
                            ImplAttributes = (MethodImplAttributes)methodDef.iflags
                        };
                        typeDefinition.Methods.Add(methodDefinition);
                        //genericParameter
                        if (methodDef.genericContainerIndex >= 0 && metadata.genericContainers != null && methodDef.genericContainerIndex < metadata.genericContainers.Length)
                        {
                            var genericContainer = metadata.genericContainers[methodDef.genericContainerIndex];
                            for (int j = 0; j < genericContainer.type_argc; j++)
                            {
                                var genericParameterIndex = genericContainer.genericParameterStart + j;
                                if (metadata.genericParameters != null && genericParameterIndex >= 0 && genericParameterIndex < metadata.genericParameters.Length)
                                {
                                    var param = metadata.genericParameters[genericParameterIndex];
                                    var genericParameter = CreateGenericParameter(param, methodDefinition);
                                    methodDefinition.GenericParameters.Add(genericParameter);
                                }
                            }
                        }
                        var methodReturnType = (methodDef.returnType >= 0 && methodDef.returnType < il2Cpp.types.Length) ? il2Cpp.types[methodDef.returnType] : null;
                        var returnType = GetTypeReferenceWithByRef(methodDefinition, methodReturnType);
                        methodDefinition.ReturnType = returnType;

                        if (addToken && typeDefinition.Module != null)
                        {
                            var customTokenAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(tokenAttribute));
                            customTokenAttribute.Fields.Add(new CustomAttributeNamedArgument("Token", new CustomAttributeArgument(stringType, $"0x{methodDef.token:X}")));
                            methodDefinition.CustomAttributes.Add(customTokenAttribute);
                        }

                        if (methodDefinition.HasBody && typeDefinition.BaseType?.FullName != "System.MulticastDelegate")
                        {
                            var ilprocessor = methodDefinition.Body.GetILProcessor();
                            if (returnType.FullName == "System.Void")
                            {
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Ret));
                            }
                            else if (returnType.IsValueType)
                            {
                                var variable = new VariableDefinition(returnType);
                                methodDefinition.Body.Variables.Add(variable);
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Ldloca_S, variable));
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Initobj, returnType));
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Ldloc_0));
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Ret));
                            }
                            else
                            {
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Ldnull));
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Ret));
                            }
                        }
                        methodDefinitionDic[i] = methodDefinition;
                        //method parameter
                        for (var j = 0; j < methodDef.parameterCount; ++j)
                        {
                            if (methodDef.parameterStart + j >= 0 && methodDef.parameterStart + j < metadata.parameterDefs.Length)
                            {
                                var parameterDef = metadata.parameterDefs[methodDef.parameterStart + j];
                                var parameterName = metadata.GetStringFromIndex(parameterDef.nameIndex);
                                if (string.IsNullOrEmpty(parameterName)) parameterName = $"param_{j}";
                                var parameterType = (parameterDef.typeIndex >= 0 && parameterDef.typeIndex < il2Cpp.types.Length) ? il2Cpp.types[parameterDef.typeIndex] : null;
                                var parameterTypeRef = GetTypeReferenceWithByRef(methodDefinition, parameterType);
                                var parameterDefinition = new ParameterDefinition(parameterName, (ParameterAttributes)(parameterType?.attrs ?? 0), parameterTypeRef);
                                methodDefinition.Parameters.Add(parameterDefinition);
                                parameterDefinitionDic[methodDef.parameterStart + j] = parameterDefinition;
                                //ParameterDefault
                                if (metadata.GetParameterDefaultValueFromIndex(methodDef.parameterStart + j, out var parameterDefault) && parameterDefault.dataIndex != -1)
                                {
                                    if (executor.TryGetDefaultValue(parameterDefault.typeIndex, parameterDefault.dataIndex, out var value))
                                    {
                                        parameterDefinition.Constant = value;
                                    }
                                    else if (typeDefinition.Module != null)
                                    {
                                        var customAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(metadataOffsetAttribute));
                                        var offset = new CustomAttributeNamedArgument("Offset", new CustomAttributeArgument(stringType, $"0x{value:X}"));
                                        customAttribute.Fields.Add(offset);
                                        parameterDefinition.CustomAttributes.Add(customAttribute);
                                    }
                                }
                            }
                        }
                        //methodAddress
                        if (!methodDefinition.IsAbstract && typeDefinition.Module != null)
                        {
                            var methodPointer = il2Cpp.GetMethodPointer(imageName, methodDef);
                            if (methodPointer > 0)
                            {
                                var customAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(addressAttribute));
                                var fixedMethodPointer = il2Cpp.GetRVA(methodPointer);
                                var rva = new CustomAttributeNamedArgument("RVA", new CustomAttributeArgument(stringType, $"0x{fixedMethodPointer:X}"));
                                var offset = new CustomAttributeNamedArgument("Offset", new CustomAttributeArgument(stringType, $"0x{il2Cpp.MapVATR(methodPointer):X}"));
                                var va = new CustomAttributeNamedArgument("VA", new CustomAttributeArgument(stringType, $"0x{methodPointer:X}"));
                                customAttribute.Fields.Add(rva);
                                customAttribute.Fields.Add(offset);
                                customAttribute.Fields.Add(va);
                                if (methodDef.slot != ushort.MaxValue)
                                {
                                    var slot = new CustomAttributeNamedArgument("Slot", new CustomAttributeArgument(stringType, methodDef.slot.ToString()));
                                    customAttribute.Fields.Add(slot);
                                }
                                methodDefinition.CustomAttributes.Add(customAttribute);
                            }
                        }
                    }
                    //property
                    var propertyEnd = typeDef.propertyStart + typeDef.property_count;
                    for (var i = typeDef.propertyStart; i < propertyEnd; ++i)
                    {
                        if (i < 0 || i >= metadata.propertyDefs.Length)
                            continue;
                        var propertyDef = metadata.propertyDefs[i];
                        var propertyName = metadata.GetStringFromIndex(propertyDef.nameIndex);
                        if (string.IsNullOrEmpty(propertyName)) propertyName = $"Property_{i}";
                        TypeReference propertyType = null;
                        MethodDefinition GetMethod = null;
                        MethodDefinition SetMethod = null;
                        if (propertyDef.get >= 0 && methodDefinitionDic.TryGetValue(typeDef.methodStart + propertyDef.get, out var getMethod))
                        {
                            GetMethod = getMethod;
                            propertyType = GetMethod.ReturnType;
                        }
                        if (propertyDef.set >= 0 && methodDefinitionDic.TryGetValue(typeDef.methodStart + propertyDef.set, out var setMethod))
                        {
                            SetMethod = setMethod;
                            if (SetMethod.Parameters.Count > 0)
                                propertyType ??= SetMethod.Parameters[0].ParameterType;
                        }
                        if (propertyType == null)
                            propertyType = (typeDefinition.Module ?? typeSystem.Object.Module).ImportReference(typeSystem.Object);
                        var propertyDefinition = new PropertyDefinition(propertyName, (PropertyAttributes)propertyDef.attrs, propertyType)
                        {
                            GetMethod = GetMethod,
                            SetMethod = SetMethod
                        };
                        typeDefinition.Properties.Add(propertyDefinition);
                        propertyDefinitionDic[i] = propertyDefinition;

                        if (addToken && typeDefinition.Module != null)
                        {
                            var customTokenAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(tokenAttribute));
                            customTokenAttribute.Fields.Add(new CustomAttributeNamedArgument("Token", new CustomAttributeArgument(stringType, $"0x{propertyDef.token:X}")));
                            propertyDefinition.CustomAttributes.Add(customTokenAttribute);
                        }
                    }
                    //event
                    var eventEnd = typeDef.eventStart + typeDef.event_count;
                    for (var i = typeDef.eventStart; i < eventEnd; ++i)
                    {
                        if (i < 0 || i >= metadata.eventDefs.Length)
                            continue;
                        var eventDef = metadata.eventDefs[i];
                        var eventName = metadata.GetStringFromIndex(eventDef.nameIndex);
                        var eventType = (eventDef.typeIndex >= 0 && eventDef.typeIndex < il2Cpp.types.Length) ? il2Cpp.types[eventDef.typeIndex] : null;
                        var eventTypeRef = GetTypeReference(typeDefinition, eventType);
                        var eventDefinition = new EventDefinition(eventName, (EventAttributes)(eventType?.attrs ?? 0), eventTypeRef);
                        if (eventDef.add >= 0 && methodDefinitionDic.TryGetValue(typeDef.methodStart + eventDef.add, out var addMethod))
                            eventDefinition.AddMethod = addMethod;
                        if (eventDef.remove >= 0 && methodDefinitionDic.TryGetValue(typeDef.methodStart + eventDef.remove, out var removeMethod))
                            eventDefinition.RemoveMethod = removeMethod;
                        if (eventDef.raise >= 0 && methodDefinitionDic.TryGetValue(typeDef.methodStart + eventDef.raise, out var raiseMethod))
                            eventDefinition.InvokeMethod = raiseMethod;
                        typeDefinition.Events.Add(eventDefinition);
                        eventDefinitionDic[i] = eventDefinition;

                        if (addToken)
                        {
                            var customTokenAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(tokenAttribute));
                            customTokenAttribute.Fields.Add(new CustomAttributeNamedArgument("Token", new CustomAttributeArgument(stringType, $"0x{eventDef.token:X}")));
                            eventDefinition.CustomAttributes.Add(customTokenAttribute);
                        }
                    }
                }
            }
            //第三遍，添加CustomAttribute
            //if (il2Cpp.Version > 20)
            //{
            //    foreach (var imageDef in metadata.imageDefs)
            //    {
            //        var typeEnd = imageDef.typeStart + imageDef.typeCount;
            //        for (int index = imageDef.typeStart; index < typeEnd; index++)
            //        {
            //            var typeDef = metadata.typeDefs[index];
            //            var typeDefinition = typeDefinitionDic[typeDef];
            //            //typeAttribute
            //            CreateCustomAttribute(imageDef, typeDef.customAttributeIndex, typeDef.token, typeDefinition.Module, typeDefinition.CustomAttributes);

            //            //field
            //            var fieldEnd = typeDef.fieldStart + typeDef.field_count;
            //            for (var i = typeDef.fieldStart; i < fieldEnd; ++i)
            //            {
            //                var fieldDef = metadata.fieldDefs[i];
            //                var fieldDefinition = fieldDefinitionDic[i];
            //                //fieldAttribute
            //                CreateCustomAttribute(imageDef, fieldDef.customAttributeIndex, fieldDef.token, typeDefinition.Module, fieldDefinition.CustomAttributes);
            //            }

            //            //method
            //            var methodEnd = typeDef.methodStart + typeDef.method_count;
            //            for (var i = typeDef.methodStart; i < methodEnd; ++i)
            //            {
            //                var methodDef = metadata.methodDefs[i];
            //                var methodDefinition = methodDefinitionDic[i];
            //                //methodAttribute
            //                CreateCustomAttribute(imageDef, methodDef.customAttributeIndex, methodDef.token, typeDefinition.Module, methodDefinition.CustomAttributes);

            //                //method parameter
            //                for (var j = 0; j < methodDef.parameterCount; ++j)
            //                {
            //                    var parameterDef = metadata.parameterDefs[methodDef.parameterStart + j];
            //                    var parameterDefinition = parameterDefinitionDic[methodDef.parameterStart + j];
            //                    //parameterAttribute
            //                    CreateCustomAttribute(imageDef, parameterDef.customAttributeIndex, parameterDef.token, typeDefinition.Module, parameterDefinition.CustomAttributes);
            //                }
            //            }

            //            //property
            //            var propertyEnd = typeDef.propertyStart + typeDef.property_count;
            //            for (var i = typeDef.propertyStart; i < propertyEnd; ++i)
            //            {
            //                var propertyDef = metadata.propertyDefs[i];
            //                var propertyDefinition = propertyDefinitionDic[i];
            //                //propertyAttribute
            //                CreateCustomAttribute(imageDef, propertyDef.customAttributeIndex, propertyDef.token, typeDefinition.Module, propertyDefinition.CustomAttributes);
            //            }

            //            //event
            //            var eventEnd = typeDef.eventStart + typeDef.event_count;
            //            for (var i = typeDef.eventStart; i < eventEnd; ++i)
            //            {
            //                var eventDef = metadata.eventDefs[i];
            //                var eventDefinition = eventDefinitionDic[i];
            //                //eventAttribute
            //                CreateCustomAttribute(imageDef, eventDef.customAttributeIndex, eventDef.token, typeDefinition.Module, eventDefinition.CustomAttributes);
            //            }
            //        }
            //    }
            //}
        }

        private TypeReference GetTypeReferenceWithByRef(MemberReference memberReference, Il2CppType il2CppType)
        {
            var moduleDefinition = memberReference?.Module ?? typeSystem.Object.Module;
            if (il2CppType == null)
            {
                return moduleDefinition.ImportReference(typeSystem.Void);
            }
            var typeReference = GetTypeReference(memberReference, il2CppType);
            if (il2CppType.byref == 1)
            {
                return new ByReferenceType(typeReference);
            }
            else
            {
                return typeReference;
            }
        }

        private TypeReference GetTypeReference(MemberReference memberReference, Il2CppType il2CppType)
        {
            var moduleDefinition = memberReference?.Module ?? typeSystem.Object.Module;
            if (il2CppType == null)
            {
                return moduleDefinition.ImportReference(typeSystem.Object);
            }
            switch (il2CppType.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_OBJECT:
                    return moduleDefinition.ImportReference(typeSystem.Object);
                case Il2CppTypeEnum.IL2CPP_TYPE_VOID:
                    return moduleDefinition.ImportReference(typeSystem.Void);
                case Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN:
                    return moduleDefinition.ImportReference(typeSystem.Boolean);
                case Il2CppTypeEnum.IL2CPP_TYPE_CHAR:
                    return moduleDefinition.ImportReference(typeSystem.Char);
                case Il2CppTypeEnum.IL2CPP_TYPE_I1:
                    return moduleDefinition.ImportReference(typeSystem.SByte);
                case Il2CppTypeEnum.IL2CPP_TYPE_U1:
                    return moduleDefinition.ImportReference(typeSystem.Byte);
                case Il2CppTypeEnum.IL2CPP_TYPE_I2:
                    return moduleDefinition.ImportReference(typeSystem.Int16);
                case Il2CppTypeEnum.IL2CPP_TYPE_U2:
                    return moduleDefinition.ImportReference(typeSystem.UInt16);
                case Il2CppTypeEnum.IL2CPP_TYPE_I4:
                    return moduleDefinition.ImportReference(typeSystem.Int32);
                case Il2CppTypeEnum.IL2CPP_TYPE_U4:
                    return moduleDefinition.ImportReference(typeSystem.UInt32);
                case Il2CppTypeEnum.IL2CPP_TYPE_I:
                    return moduleDefinition.ImportReference(typeSystem.IntPtr);
                case Il2CppTypeEnum.IL2CPP_TYPE_U:
                    return moduleDefinition.ImportReference(typeSystem.UIntPtr);
                case Il2CppTypeEnum.IL2CPP_TYPE_I8:
                    return moduleDefinition.ImportReference(typeSystem.Int64);
                case Il2CppTypeEnum.IL2CPP_TYPE_U8:
                    return moduleDefinition.ImportReference(typeSystem.UInt64);
                case Il2CppTypeEnum.IL2CPP_TYPE_R4:
                    return moduleDefinition.ImportReference(typeSystem.Single);
                case Il2CppTypeEnum.IL2CPP_TYPE_R8:
                    return moduleDefinition.ImportReference(typeSystem.Double);
                case Il2CppTypeEnum.IL2CPP_TYPE_STRING:
                    return moduleDefinition.ImportReference(typeSystem.String);
                case Il2CppTypeEnum.IL2CPP_TYPE_TYPEDBYREF:
                    return moduleDefinition.ImportReference(typeSystem.TypedReference);
                case Il2CppTypeEnum.IL2CPP_TYPE_CLASS:
                case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                    {
                        try
                        {
                            var idx = (int)il2CppType.datapoint;
                            if (idx >= 0 && idx < metadata.typeDefs.Length)
                            {
                                var typeDef = metadata.typeDefs[idx];
                                if (typeDefinitionDic.TryGetValue(typeDef, out var typeDefinition))
                                {
                                    return moduleDefinition.ImportReference(typeDefinition);
                                }
                            }
                        }
                        catch { }
                        return moduleDefinition.ImportReference(typeSystem.Object);
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_ARRAY:
                case Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
                    {
                        try
                        {
                            var oriType = il2Cpp.ResolveType(il2CppType.datapoint);
                            return new ArrayType(GetTypeReference(memberReference, oriType));
                        }
                        catch
                        {
                            return moduleDefinition.ImportReference(typeSystem.Object);
                        }
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_PTR:
                    {
                        try
                        {
                            var oriType = il2Cpp.ResolveType(il2CppType.datapoint);
                            return new PointerType(GetTypeReference(memberReference, oriType));
                        }
                        catch
                        {
                            return moduleDefinition.ImportReference(typeSystem.IntPtr);
                        }
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_VAR:
                case Il2CppTypeEnum.IL2CPP_TYPE_MVAR:
                    {
                        try
                        {
                            var genericParam = executor.GetGenericParameteFromIl2CppType(il2CppType);
                            if (genericParam != null)
                            {
                                var pname = metadata.GetStringFromIndex(genericParam.nameIndex);
                                if (memberReference is MethodDefinition methodDefinition)
                                {
                                    var match = methodDefinition.GenericParameters.FirstOrDefault(x => x.Name == pname);
                                    if (match != null)
                                        return match;
                                    var matchType = methodDefinition.DeclaringType?.GenericParameters.FirstOrDefault(x => x.Name == pname);
                                    if (matchType != null)
                                        return matchType;
                                }
                                else if (memberReference is TypeDefinition typeDefinition)
                                {
                                    var match = typeDefinition.GenericParameters.FirstOrDefault(x => x.Name == pname);
                                    if (match != null)
                                        return match;
                                }
                            }
                        }
                        catch { }
                        return moduleDefinition.ImportReference(typeSystem.Object);
                    }
                default:
                    return moduleDefinition.ImportReference(typeSystem.Object);
            }
        }

        private void CreateCustomAttribute(Il2CppImageDefinition imageDef, int customAttributeIndex, uint token, ModuleDefinition moduleDefinition, Collection<CustomAttribute> customAttributes)
        {
            var attributeIndex = metadata.GetCustomAttributeIndex(imageDef, customAttributeIndex, token);
            if (attributeIndex >= 0)
            {
                try
                {
                    if (il2Cpp.Version < 29)
                    {
                        var attributeTypeRange = metadata.attributeTypeRanges[attributeIndex];
                        for (int i = 0; i < attributeTypeRange.count; i++)
                        {
                            var attributeTypeIndex = metadata.attributeTypes[attributeTypeRange.start + i];
                            var attributeType = il2Cpp.types[attributeTypeIndex];
                            var typeDef = executor.GetTypeDefinitionFromIl2CppType(attributeType);
                            var typeDefinition = typeDefinitionDic[typeDef];
                            if (!TryRestoreCustomAttribute(typeDefinition, moduleDefinition, customAttributes))
                            {
                                var methodPointer = executor.customAttributeGenerators[attributeIndex];
                                var fixedMethodPointer = il2Cpp.GetRVA(methodPointer);
                                var customAttribute = new CustomAttribute(moduleDefinition.ImportReference(attributeAttribute));
                                var name = new CustomAttributeNamedArgument("Name", new CustomAttributeArgument(stringType, typeDefinition.Name));
                                var rva = new CustomAttributeNamedArgument("RVA", new CustomAttributeArgument(stringType, $"0x{fixedMethodPointer:X}"));
                                var offset = new CustomAttributeNamedArgument("Offset", new CustomAttributeArgument(stringType, $"0x{il2Cpp.MapVATR(methodPointer):X}"));
                                customAttribute.Fields.Add(name);
                                customAttribute.Fields.Add(rva);
                                customAttribute.Fields.Add(offset);
                                customAttributes.Add(customAttribute);
                            }
                        }
                    }
                    else
                    {
                        var startRange = metadata.attributeDataRanges[attributeIndex];
                        var endRange = metadata.attributeDataRanges[attributeIndex + 1];
                        metadata.Position = (il2Cpp.Version < 38 ? metadata.header.attributeDataOffset : metadata.header.attributeData.offset) + startRange.startOffset;
                        var buff = metadata.ReadBytes((int)(endRange.startOffset - startRange.startOffset));
                        var reader = new CustomAttributeDataReader(executor, buff);
                        if (reader.Count != 0)
                        {
                            var iterator = reader.VisitCustomAttributeData();
                            foreach (var visitor in iterator)
                            {
                                var methodDefinition = methodDefinitionDic[visitor.CtorIndex];
                                var customAttribute = new CustomAttribute(moduleDefinition.ImportReference(methodDefinition));
                                foreach (var argument in visitor.Arguments)
                                {
                                    var parameterDefinition = methodDefinition.Parameters[argument.Index];
                                    var customAttributeArgument = CreateCustomAttributeArgument(parameterDefinition.ParameterType, argument.Value, methodDefinition);
                                    customAttribute.ConstructorArguments.Add(customAttributeArgument);
                                }
                                foreach (var field in visitor.Fields)
                                {
                                    var fieldDefinition = fieldDefinitionDic[field.Index];
                                    var customAttributeArgument = CreateCustomAttributeArgument(fieldDefinition.FieldType, field.Value, fieldDefinition);
                                    var customAttributeNamedArgument = new CustomAttributeNamedArgument(fieldDefinition.Name, customAttributeArgument);
                                    customAttribute.Fields.Add(customAttributeNamedArgument);
                                }
                                foreach (var property in visitor.Properties)
                                {
                                    var propertyDefinition = propertyDefinitionDic[property.Index];
                                    var customAttributeArgument = CreateCustomAttributeArgument(propertyDefinition.PropertyType, property.Value, propertyDefinition);
                                    var customAttributeNamedArgument = new CustomAttributeNamedArgument(propertyDefinition.Name, customAttributeArgument);
                                    customAttribute.Properties.Add(customAttributeNamedArgument);
                                }
                                customAttributes.Add(customAttribute);
                            }
                        }
                    }
                }
                catch
                {
                    Console.WriteLine($"ERROR: Error while restoring attributeIndex {attributeIndex}");
                }
            }
        }

        private static bool TryRestoreCustomAttribute(TypeDefinition attributeType, ModuleDefinition moduleDefinition, Collection<CustomAttribute> customAttributes)
        {
            if (attributeType.Methods.Count == 1 && attributeType.Name != "CompilerGeneratedAttribute")
            {
                var methodDefinition = attributeType.Methods[0];
                if (methodDefinition.Name == ".ctor" && methodDefinition.Parameters.Count == 0)
                {
                    var customAttribute = new CustomAttribute(moduleDefinition.ImportReference(methodDefinition));
                    customAttributes.Add(customAttribute);
                    return true;
                }
            }
            return false;
        }

        private GenericParameter CreateGenericParameter(Il2CppGenericParameter param, IGenericParameterProvider iGenericParameterProvider)
        {
            if (!genericParameterDic.TryGetValue(param, out var genericParameter))
            {
                var genericName = metadata.GetStringFromIndex(param.nameIndex);
                genericParameter = new GenericParameter(genericName, iGenericParameterProvider)
                {
                    Attributes = (GenericParameterAttributes)param.flags
                };
                genericParameterDic[param] = genericParameter;
                for (int i = 0; i < param.constraintsCount; ++i)
                {
                    var il2CppType = il2Cpp.types[metadata.constraintIndices[param.constraintsStart + i].index];
                    genericParameter.Constraints.Add(new GenericParameterConstraint(GetTypeReference((MemberReference)iGenericParameterProvider, il2CppType)));
                }
            }
            return genericParameter;
        }

        private CustomAttributeArgument CreateCustomAttributeArgument(TypeReference typeReference, BlobValue blobValue, MemberReference memberReference)
        {
            var val = blobValue.Value;
            if (typeReference.FullName == "System.Object")
            {
                if (blobValue.il2CppTypeEnum == Il2CppTypeEnum.IL2CPP_TYPE_IL2CPP_TYPE_INDEX)
                {
                    val = new CustomAttributeArgument(memberReference.Module.ImportReference(typeof(Type)), GetTypeReference(memberReference, (Il2CppType)val));
                }
                else
                {
                    val = new CustomAttributeArgument(GetBlobValueTypeReference(blobValue, memberReference), val);
                }
            }
            else if (val == null)
            {
                return new CustomAttributeArgument(typeReference, val);
            }
            else if (typeReference is ArrayType arrayType)
            {
                var arrayVal = (BlobValue[])val;
                var array = new CustomAttributeArgument[arrayVal.Length];
                var elementType = arrayType.ElementType;
                for (int i = 0; i < arrayVal.Length; i++)
                {
                    array[i] = CreateCustomAttributeArgument(elementType, arrayVal[i], memberReference);
                }
                val = array;
            }
            else if (typeReference.FullName == "System.Type")
            {
                val = GetTypeReference(memberReference, (Il2CppType)val);
            }
            return new CustomAttributeArgument(typeReference, val);
        }

        private TypeReference GetBlobValueTypeReference(BlobValue blobValue, MemberReference memberReference)
        {
            if (blobValue.EnumType != null)
            {
                return GetTypeReference(memberReference, blobValue.EnumType);
            }
            var il2CppType = new Il2CppType
            {
                type = blobValue.il2CppTypeEnum
            };
            return GetTypeReference(memberReference, il2CppType);
        }
    }
}
