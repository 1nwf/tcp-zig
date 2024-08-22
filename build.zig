const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "tcp-zig",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.linkLibC();

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    try run_cmd.argv.insert(b.allocator, 0, std.Build.Step.Run.Arg{ .bytes = @constCast("sudo") });

    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
}

const TunDevice = struct {
    b: *std.Build,
    step: std.Build.step,
    name: []const u8,

    pub fn init(b: *std.Build) !TunDevice {
        const tapdev = try b.allocator.create(TunDevice);
        tapdev.* = .{
            .b = b,
            .step = std.Build.Step.init(.{
                .id = .custom,
                .name = "create tun device",
                .makeFn = makeFn,
                .owner = b,
            }),
        };

        return .{ .b = b, .step = std.Build.Step.create() };
    }

    fn makeFn(step: *std.Build.Step, _: std.Progress.Node) !void {
        const self: *TunDevice = @fieldParentPtr("step", step);
        _ = self;
    }
};
