# Star Rail Metadata Reconstructor

A `global-metadata.dat` rebuilder for Honkai: Star Rail.

## How Honkai: Star Rail stores IL2CPP metadata

Honkai: Star Rail does not keep all IL2CPP metadata in the standard Unity
layout. The information needed for a complete dump is split between
`global-metadata.dat`, `startup-metadata.dat`, and `GameAssembly.dll`.

The metadata tables are encoded separately rather than protected by one XOR
over the entire file. Depending on the table, values are decoded with a mix of
XOR, addition, subtraction, and keys derived from the record index. Strings and
string literals use rolling 64-bit XOR keys, while tables such as types, fields,
methods, properties, events, and generics use their own record layouts and
decoding formulas.

`GameAssembly.dll` contains an `MHY` header whose encoded values locate many of
these tables. It also contains runtime-only IL2CPP data such as type records,
generic instantiations, method pointers, and registration structures.
`startup-metadata.dat` supplies additional records such as image and generic
class mappings.

The reconstructor discovers the current build layout, decodes the tables, and
writes them back as IL2CPP v24.2 metadata. Runtime data that cannot be stored in
`global-metadata.dat` is written to sidecar files and a runtime profile for the
included modified Il2CppDumper.

The relevant implementation is organized under:

- [`src/discovery`](src/discovery) for build and runtime layout discovery
- [`src/reconstruction`](src/reconstruction) for table decoding and rebuilding
- [`src/output`](src/output) for metadata and sidecar generation
- [`src/pipeline`](src/pipeline) for the reconstruction and validation flow
- [`Il2CppDumper`](Il2CppDumper) for the modified dumper

## Technical overview

### Input files

| File | What the reconstructor reads from it |
| --- | --- |
| `global-metadata.dat` | Encoded strings, literals, types, fields, methods, parameters, properties, events, defaults, interfaces, vtables, and generic metadata |
| `startup-metadata.dat` | Image records and generic-class mappings |
| `GameAssembly.dll` | The `MHY` header, executable address ranges, method pointers, IL2CPP registrations, runtime types, and generic instantiations |

The files must come from the same game build because their indices and runtime
addresses refer to one another.

### MHY header and build discovery

The reconstructor searches `GameAssembly.dll` for `MHY\0` candidates followed
by 150 little-endian 32-bit values. These values do not contain normal table
offsets directly. Each table uses its own transformation. Examples from
[`src/discovery/mhy.rs`](src/discovery/mhy.rs) include:

```text
string table       = mhy[109] - 1924946706
image table        = mhy[84]  + 0xD882615E
image count        = (mhy[77] ^ 0x10210728) / 40
type table         = mhy[33]  ^ 0x68531D3F
field table        = mhy[8]   - 1292050039
method table       = mhy[83]  - 207601004
parameter table    = mhy[12]  - 587858498
generic parameters = mhy[80]  - 626232567
generic containers = mhy[60]  - 1656188401
```

All arithmetic uses the same wrapping 32-bit behavior as the game.

The discovery code validates each header candidate against the supplied files.
It determines the metadata prefix by testing decoded image names, derives table
counts from their relationships, reads executable ranges from the PE image, and
searches for the method-pointer and IL2CPP registration structures. It also
detects whether runtime type and generic-instantiation tables are inline or
pointer-based. CLI and profile overrides remain available when a future build
cannot be resolved completely.

### Strings and string literals

A metadata string index stores both its byte length and its offset:

```text
negative index: length = (index >> 23) & 0xFF, offset = index & 0x007FFFFF
positive index: length = (index >> 25) & 0x3F, offset = index & 0x01FFFFFF
```

The encrypted bytes are read in eight-byte blocks. The first XOR key depends on
the string offset, and a fixed step is added after every block:

```text
key  = offset * 0x907C49622D94D21A + 0x75B679DAF67C3F24
step = 0x3E693CD23A41FDEF

plain_block = encrypted_block ^ key
key         = key + step
```

String literals use a separate index-derived offset transform and rolling XOR
schedule. The implementation for both formats is in
[`src/reconstruction/strings.rs`](src/reconstruction/strings.rs) and
[`src/reconstruction/literals.rs`](src/reconstruction/literals.rs).

### Metadata records

Star Rail replaces the standard IL2CPP structures with smaller packed records.
The reconstructor decodes them and expands them into the v24.2 layouts expected
by Il2CppDumper.

| Record | Star Rail size | Reconstructed data |
| --- | ---: | --- |
| Type definition | 70 bytes | Names, parent and declaring types, flags, generic container, member ranges, interfaces, vtable, and nesting |
| Field | 8 bytes | Name, runtime type index, token, and field offset sidecar entry |
| Method | 26 bytes | Name, return type, parameters, flags, slot, token, and generic container |
| Parameter | 8 bytes | Name, runtime type index, and token |
| Generic parameter | 14 bytes | Name, owner container, ordinal, flags, and constraints |
| Generic container | 16 bytes | Type or method owner and its parameter range |
| Property | 10 bytes | Name, getter, setter, attributes, and token |
| Event | 14 bytes | Name, event type, accessors, and token |

Most fields use record-index-derived keys combined with wrapping XOR,
addition, or subtraction. Type classification is reconstructed by resolving
the actual `System.Enum` and `System.ValueType` runtime type indices, then
deriving class, struct, enum, interface, abstract, sealed, and nested flags.
See [`src/reconstruction/types.rs`](src/reconstruction/types.rs),
[`src/reconstruction/methods.rs`](src/reconstruction/methods.rs), and
[`src/reconstruction/generics.rs`](src/reconstruction/generics.rs).

#### Parameter names

Parameter names are stripped from the shipped metadata. Every encoded
parameter-name field resolves to `0xFFFFFFFF`, IL2CPP's explicit no-string
sentinel.

Because the original names are unavailable, the modified Il2CppDumper uses
`a1`, `a2`, and so on in `dump.cs`. DummyDll parameters use `param_0`, `param_1`,
and so on.

### Runtime mappings

Method bodies and some generic information exist only in `GameAssembly.dll`.
The reconstructor locates the primary indirect method-pointer table and the
fallback direct table dynamically. Valid non-generic method addresses are
written as `(method index, virtual address)` records. Generic classes are
connected to runtime generic instantiations through mappings recovered from
`startup-metadata.dat`.

The runtime profile tells the modified Il2CppDumper where the current build's
code registration, metadata registration, method-pointer table, runtime type
table, and generic-instantiation table are located. This avoids embedding one
build's virtual addresses in the dumper.

### Generated files

| Output | Purpose |
| --- | --- |
| `rebuilt_metadata.dat` | Standard IL2CPP v24.2 metadata with magic `0xFAB11BAF` and reconstructed metadata sections |
| `field_offsets.bin` | Twelve-byte records containing type index, field index within the type, and runtime offset |
| `method_mappings.bin` | Twelve-byte records containing method index and 64-bit method address |
| `generic_classes.bin` | Eight-byte records connecting a type definition to a runtime generic-instantiation index |
| `runtime-profile.json` | Discovered runtime addresses, counts, and table-layout information used by the modified Il2CppDumper |

The binary sidecars are required because those values are runtime data and do
not have equivalent fields in a standard `global-metadata.dat` file. They are
consumed directly by the included modified Il2CppDumper.

The normal workflow is:

```text
global-metadata.dat + startup-metadata.dat + matching GameAssembly.dll
                              |
                              v
                StarRailMetadataReconstructor
                              |
                              v
 rebuilt_metadata.dat + runtime sidecars + runtime profile
                              |
                              v
                    modified Il2CppDumper
                              |
                              v
                    dump.cs / DummyDll
```

## Build

```powershell
cargo build --release
dotnet build Il2CppDumper/Il2CppDumper.csproj -c Release -f net8.0
```

## Current two-stage usage

```powershell
target/release/star_rail_metadata_reconstructor.exe `
  global-metadata.dat `
  GameAssembly.dll `
  startup-metadata.dat `
  --output-dir work `
  --write-runtime-profile work/runtime-profile.json

Il2CppDumper/bin/Release/net8.0/Il2CppDumper.exe `
  GameAssembly.dll `
  work/rebuilt_metadata.dat `
  DumperOutput `
  --runtime-profile work/runtime-profile.json `
  --sidecar-dir work
```

All three input files must belong to the same game build. A mismatched
`GameAssembly.dll` can still look structurally valid while producing incorrect
type flags, generic types, parameters, and offsets.
