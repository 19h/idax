# First-Time User Tutorial Path

## Step 1: Open database and wait analysis

```cpp
ida::database::init(argc, argv);
ida::database::open(input_path, true);
ida::analysis::wait();
```

## Step 2: Navigate program structure

```cpp
for (auto seg : ida::segment::all()) {
  // inspect seg.name(), seg.start(), seg.end()
}
for (auto fn : ida::function::all()) {
  // inspect fn.name(), fn.start(), fn.end()
}
```

## Step 3: Inspect and annotate

```cpp
auto ea = ida::name::resolve("main");
if (ea) {
  ida::comment::set(*ea, "tutorial marker");
  auto insn = ida::instruction::decode(*ea);
}
```

## Step 4: Search and cross-reference

```cpp
ida::search::TextOptions opts;
opts.regex = true;
auto hit = ida::search::text("main", ida::database::min_address().value(), opts);
```

## Step 5: Save and close

```cpp
ida::database::save();
ida::database::close(true);
```
