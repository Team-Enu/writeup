function f()
  print("Hello, world!")
end
f()
f()
cargo(f, 4)
f()  -- expect crash
