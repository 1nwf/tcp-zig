const builtin = @import("builtin");

pub usingnamespace switch (builtin.target.os.tag) {
    // .macos => @import("macos.zig"),
    .linux => @import("linux.zig"),
    else => @compileError("invalid os"),
};
