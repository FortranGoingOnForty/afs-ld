An unresolved weak reference with a collision-resistant intentionally missing
name is permitted under dynamic lookup and materialized as a weak flat-namespace
GOT bind. Both linkers must leave the slot zero before dyld processing, preserve
weak undefined symbol metadata, and return zero when the provider is absent.

tolerated:
  - region: __TEXT,__text bytes 0x0-0x3 reason: "layout-dependent ADRP immediate; page-ref and runtime checks validate the GOT load"
