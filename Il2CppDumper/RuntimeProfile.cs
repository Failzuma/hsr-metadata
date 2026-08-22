using System.Text.Json.Serialization;

namespace Il2CppDumper
{
    public class RuntimeProfile
    {
        [JsonPropertyName("code_registration_va")]
        public ulong CodeRegistrationVa { get; set; }
        [JsonPropertyName("metadata_registration_va")]
        public ulong MetadataRegistrationVa { get; set; }
        [JsonPropertyName("method_pointers_va")]
        public ulong MethodPointersVa { get; set; }
        [JsonPropertyName("method_pointers_count")]
        public long MethodPointersCount { get; set; }
        [JsonPropertyName("types_va")]
        public ulong TypesVa { get; set; }
        [JsonPropertyName("types_count")]
        public long TypesCount { get; set; }
        [JsonPropertyName("generic_insts_va")]
        public ulong GenericInstsVa { get; set; }
        [JsonPropertyName("generic_insts_count")]
        public long GenericInstsCount { get; set; }
        [JsonPropertyName("generic_insts_are_inline")]
        public bool GenericInstsAreInline { get; set; }
        [JsonPropertyName("types_are_inline")]
        public bool TypesAreInline { get; set; }
        [JsonPropertyName("generic_class_source_offset")]
        public long GenericClassSourceOffset { get; set; }
        [JsonPropertyName("generic_class_count")]
        public long GenericClassCount { get; set; }
    }
}
