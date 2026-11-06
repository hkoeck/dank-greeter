.pragma library

// Decides whether a PAM auth stack may be run before the user has asked for
// anything. Opening a greetd session runs every module in the stack, so on a
// stack that can act by itself that costs a face scan, a reader touch or a push
// to a phone for a request nobody made - and on one that can succeed by itself,
// a login nobody asked for.
//
// Three classes, mirroring promptingAuthModules and inertAuthModules in
// dux-shell's core/internal/pam, which gates the lock screen the same way.
// A prompting module cannot succeed without asking the user for something. An
// inert one never authenticates anybody and does nothing the user would notice
// if it ran unasked. Everything else is unknown, and unknown closes the gate:
// pam_duo pushes to a phone, pam_pkcs11 can answer from a card, pam_exec runs
// whatever it likes, and none of them would be on a blocklist somebody
// remembered to write.
const PROMPTING_AUTH_MODULES = ["pam_unix", "libpinpam", "pinpam", "pam_sss"];

// An inert module is not automatically harmless, which is why the control field
// is read as well: "sufficient pam_permit.so" grants everyone, and
// "sufficient pam_succeed_if.so user ingroup nopasswdlogin" is how passwordless
// login is wired. Those are inert modules in a position where their success
// ends the stack, and isPromptOnly rejects that.
const INERT_AUTH_MODULES = ["pam_faillock", "pam_tally2", "pam_faildelay", "pam_deny", "pam_warn", "pam_nologin", "pam_securetty", "pam_sepermit", "pam_localuser", "pam_usertype", "pam_succeed_if", "pam_permit", "pam_shells", "pam_time", "pam_access", "pam_pwquality", "pam_pwhistory", "pam_cracklib", "pam_env", "pam_keyinit", "pam_limits", "pam_loginuid", "pam_selinux", "pam_namespace", "pam_umask", "pam_lastlog", "pam_lastlog2", "pam_motd", "pam_mail", "pam_systemd", "pam_mkhomedir", "pam_echo", "pam_debug", "pam_gnome_keyring", "pam_kwallet", "pam_kwallet5", "pam_oo7", "pam_ecryptfs", "libpinpam_master_key"];

function stripComment(line) {
    if (!line)
        return "";
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#"))
        return "";
    const hashIdx = trimmed.indexOf("#");
    if (hashIdx >= 0)
        return trimmed.substring(0, hashIdx).trim();
    return trimmed;
}

// The control field of a directive - "required", or a bracketed
// "[success=done default=ignore]" - as the list of tokens inside it.
function controlTokens(fields) {
    if (fields.length < 2)
        return [];
    if (!fields[1].startsWith("["))
        return [fields[1]];
    const tokens = [fields[1].substring(1)];
    for (let i = 2; i < fields.length; i++) {
        if (fields[i].endsWith("]")) {
            tokens.push(fields[i].slice(0, -1));
            return tokens;
        }
        tokens.push(fields[i]);
    }
    return tokens;
}

// the stack ends successfully the moment this module succeeds
function controlEndsStack(tokens) {
    if (tokens.length === 1)
        return tokens[0] === "sufficient";
    return tokens.indexOf("success=done") >= 0;
}

// the stack cannot succeed unless this module does
function controlIsDecisive(tokens) {
    if (tokens.length === 1)
        return ["required", "requisite", "sufficient", "binding"].indexOf(tokens[0]) >= 0;
    return tokens.some(token => token.startsWith("success=") && token !== "success=ignore" && token !== "success=bad" && token !== "success=die");
}

// Every auth directive the stack reaches as {module, endsStack, decisive}, or
// null when any part of it could not be read: an include the caller keeps no
// copy of, a file that failed to load. Null is the honest answer there, and the
// caller treats it as "assume the stack can act on its own". Unlike the lock
// screen, which asks `dms auth validate`, this walk can only follow includes
// into the files the greeter keeps - a stack built on a custom substack
// therefore waits for a submit, exactly as it did before.
function resolveAuthLines(stackText, includedTexts) {
    if (!stackText)
        return null;
    const pending = [stackText];
    const visited = [];
    const lines = [];
    while (pending.length > 0) {
        const text = pending.shift().split(/\r?\n/);
        for (let i = 0; i < text.length; i++) {
            const line = stripComment(text[i]);
            if (!line)
                continue;
            const fields = line.split(/\s+/);
            let target = "";
            if (fields[0] === "@include")
                target = fields[1] || "";
            else if (fields[0].replace(/^-/, "") !== "auth")
                continue;
            else if (fields[1] === "include" || fields[1] === "substack")
                target = fields[2] || "";
            if (target !== "") {
                if (visited.indexOf(target) >= 0)
                    continue;
                visited.push(target);
                const included = includedTexts[target];
                if (!included)
                    return null;
                pending.push(included);
                continue;
            }
            for (let f = 1; f < fields.length; f++) {
                if (!fields[f].endsWith(".so"))
                    continue;
                const control = controlTokens(fields);
                lines.push({
                    module: fields[f].split("/").pop().slice(0, -3),
                    endsStack: controlEndsStack(control),
                    decisive: controlIsDecisive(control)
                });
                break;
            }
        }
    }
    return lines;
}

// The modules in the stack that neither list vouches for.
function unvettedModules(lines) {
    if (!lines)
        return [];
    return lines.map(line => line.module).filter(name => PROMPTING_AUTH_MODULES.indexOf(name) < 0 && INERT_AUTH_MODULES.indexOf(name) < 0);
}

// Whether opening this stack only buys the prompt and nothing else: every
// module vetted, no module that cannot prompt sitting where its success would
// end the stack, and at least one module that does prompt that the stack
// depends on.
function isPromptOnly(lines) {
    if (!lines || lines.length === 0 || unvettedModules(lines).length > 0)
        return false;
    let asksSomething = false;
    for (let i = 0; i < lines.length; i++) {
        const prompts = PROMPTING_AUTH_MODULES.indexOf(lines[i].module) >= 0;
        if (!prompts && lines[i].endsStack)
            return false;
        if (prompts && lines[i].decisive)
            asksSomething = true;
    }
    return asksSomething;
}
