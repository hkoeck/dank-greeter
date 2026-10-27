import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import test from "node:test";

const gate = vm.createContext({});
vm.runInContext(readFileSync(new URL("../Modules/Greetd/PamGate.js", import.meta.url), "utf8").replace(/^\.pragma.*$/m, ""), gate);

// Fedora's password-auth verbatim: bracket controls, helper modules that cannot
// let anyone in from where they sit, pam_unix doing the asking.
const fedoraPasswordAuth = [
    "auth        required                             pam_env.so",
    "auth        required                             pam_faildelay.so delay=2000000",
    "auth        [default=1 ignore=ignore success=ok] pam_usertype.so isregular",
    "auth        [default=1 ignore=ignore success=ok] pam_localuser.so",
    "auth        sufficient                           pam_unix.so nullok",
    "auth        [default=1 ignore=ignore success=ok] pam_usertype.so isregular",
    "auth        sufficient                           pam_sss.so forward_pass",
    "auth        required                             pam_deny.so",
    "account     required                             pam_unix.so",
    ""
].join("\n");

const fedoraSystemAuth = fedoraPasswordAuth.replace("auth        [default=1 ignore=ignore success=ok] pam_usertype.so isregular", "auth        sufficient                           pam_fprintd.so\nauth        [default=1 ignore=ignore success=ok] pam_usertype.so isregular");

const stacks = {
    "password-auth": fedoraPasswordAuth,
    "system-auth": fedoraSystemAuth,
    postlogin: "session optional pam_umask.so silent\n"
};

// values cross the vm context boundary, so compare them structurally
const plain = value => JSON.parse(JSON.stringify(value));
const promptOnly = (text, included = stacks) => gate.isPromptOnly(gate.resolveAuthLines(text, included));

test("a distro stack where everything asks or stands aside is prompt-only", () => {
    assert.equal(promptOnly("auth include password-auth\n"), true);
    assert.equal(promptOnly("auth substack password-auth\nauth include postlogin\n"), true);
    // the managed greetd stack: a PIN module in front of the distro stack
    assert.equal(promptOnly("auth sufficient libpinpam.so\nauth substack password-auth\nauth optional pam_gnome_keyring.so\n"), true);
});

test("a stack that can authenticate on its own waits for a submit", () => {
    // these have their own context in the greeter and must not be run by opening
    // a conversation for the prompt
    assert.equal(promptOnly("auth include system-auth\n"), false, "inline pam_fprintd");
    assert.equal(promptOnly("auth sufficient pam_howdy.so\nauth include password-auth\n"), false);
    assert.equal(promptOnly("auth sufficient pam_u2f.so\nauth include password-auth\n"), false);
});

test("a module nobody has vetted closes the gate", () => {
    for (const module of ["pam_duo.so", "pam_pkcs11.so", "pam_yubico.so", "pam_ssh_agent_auth.so", "pam_sss_gss.so", "pam_exec.so"]) {
        const text = `auth required ${module}\nauth include password-auth\n`;
        assert.equal(promptOnly(text), false, module);
        assert.deepEqual(plain(gate.unvettedModules(gate.resolveAuthLines(text, stacks))), [module.slice(0, -3)]);
    }
});

test("a module that cannot prompt may not be the one that ends the stack", () => {
    // exactly how passwordless login is wired, and neither module is on a blocklist
    assert.equal(promptOnly("auth sufficient pam_succeed_if.so user ingroup nopasswdlogin\nauth include password-auth\n"), false);
    assert.equal(promptOnly("auth sufficient pam_permit.so\nauth include password-auth\n"), false);
    assert.equal(promptOnly("auth [success=done default=ignore] pam_localuser.so\nauth include password-auth\n"), false);
    // the same modules on the controls the distros give them are fine
    assert.equal(promptOnly("auth [default=1 ignore=ignore success=ok] pam_localuser.so\nauth include password-auth\n"), true);
});

test("a stack with nothing in it that asks is not prompt-only", () => {
    assert.equal(promptOnly("auth required pam_permit.so\nauth optional pam_env.so\n"), false);
    assert.equal(promptOnly("account required pam_unix.so\n"), false);
});

test("anything this walk cannot read is a no", () => {
    assert.equal(gate.resolveAuthLines("", stacks), null);
    assert.equal(gate.resolveAuthLines("auth include some-custom-substack\n", stacks), null);
    assert.equal(promptOnly("auth include some-custom-substack\n"), false);
});

test("include forms and cycles", () => {
    // Debian's @include applies to every phase
    assert.equal(promptOnly("@include common-auth\n", {
        "common-auth": "auth [success=1 default=ignore] pam_unix.so nullok\nauth requisite pam_deny.so\nauth required pam_permit.so\n"
    }), true);
    // a stack that includes itself must not hang
    assert.equal(promptOnly("auth include loop\n", {
        loop: "auth include loop\nauth sufficient pam_unix.so\n"
    }), true);
    // a module given by absolute path is the same module
    assert.equal(promptOnly("auth sufficient /usr/lib64/security/pam_unix.so\n"), true);
    // a leading dash marks an optional module file, the directive still counts
    assert.equal(promptOnly("-auth sufficient pam_duo.so\nauth include password-auth\n"), false);
});
