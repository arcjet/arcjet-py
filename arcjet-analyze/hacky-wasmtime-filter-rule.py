from wasmtime import Engine, Store
from wasmtime import component as cm

COMPONENT_WASM = "arcjet_analyze_js_req.component.wasm"

engine = Engine()
store = Store(engine)
linker = cm.Linker(engine)
linker.allow_shadowing = True


def ip_lookup(_store, ip):
    return None


component = cm.Component.from_file(engine, COMPONENT_WASM)

# Define traps for all imports first
linker.define_unknown_imports_as_traps(component)

# Override the import we care about, shadowing the trap.
# The namespace is flattened: "arcjet:js-req/filter-overrides"
with linker.root() as root:
    with root.add_instance("arcjet:js-req/filter-overrides") as iface:
        iface.add_func("ip-lookup", ip_lookup)

instance = linker.instantiate(store, component)

match_filters = instance.get_func(store, "match-filters")

if match_filters is None:
    raise RuntimeError("match-filters export not found in component")

result = match_filters(store, '{"protocol":"http"}', ['protocol == "http"'], True)

print(f"result is {result}")
