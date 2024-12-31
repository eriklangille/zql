const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding });
    const optimize = b.standardOptimizeOption(.{});

    const wasm = b.addExecutable(.{
        .name = "zql",
        .root_source_file = b.path("zql.zig"),
        .target = target,
        .optimize = optimize,
    });
    wasm.rdynamic = true;
    wasm.entry = .disabled;

    const debug = b.option(bool, "debug", "Debug mode - application logging") orelse false;
    const options = b.addOptions();
    options.addOption(bool, "is_debug", debug);
    wasm.root_module.addOptions("config", options);

    b.installArtifact(wasm);
}
