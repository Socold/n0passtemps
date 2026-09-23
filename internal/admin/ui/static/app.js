/*
 * Administration interface behaviour.
 *
 * Four additions, and nothing else. Three of them are conveniences and every
 * screen works with this file blocked or disabled: the confirmations are a
 * second thought before something final, the filter submission saves a click on
 * a form that already has a button, and the copy control sits beside text the
 * operator can select by hand.
 *
 * The fourth, the passkey ceremonies, is the one thing here that cannot be done
 * without script, because navigator.credentials runs in the browser between the
 * two halves of a ceremony. Its controls are rendered hidden and revealed here,
 * so a browser without WebAuthn, or with this file blocked, shows no button that
 * would do nothing; the pasted token stays on the sign-in screen either way, and
 * is what an operator falls back to.
 *
 * The file is served from the embedded filesystem because the Content Security
 * Policy allows script only from this origin and forbids an inline script and an
 * inline event handler. There is no build step and no dependency; ADR 0012
 * explains why.
 */

(function () {
  "use strict";

  /*
   * Confirmation before something that cannot be undone.
   *
   * The prompt is read from the form rather than written here, so the wording
   * sits beside the action it describes and a new action cannot inherit the
   * wrong sentence. Without this file the action still happens: the server is
   * what decides, and a browser dialogue is a courtesy, never a control.
   */
  function wireConfirmations(root) {
    var forms = root.querySelectorAll("form[data-confirm]");
    for (var i = 0; i < forms.length; i++) {
      forms[i].addEventListener("submit", function (event) {
        var question = event.currentTarget.getAttribute("data-confirm");
        if (question && !window.confirm(question)) {
          event.preventDefault();
        }
      });
    }
  }

  /*
   * Submit a filter form as soon as a choice changes.
   *
   * Only select and checkbox controls trigger it. Doing the same for a text
   * field would submit the form on every keystroke, which on the history screen
   * means a query per character.
   */
  function wireFilters(root) {
    var forms = root.querySelectorAll("form[data-autosubmit]");
    for (var i = 0; i < forms.length; i++) {
      (function (form) {
        form.addEventListener("change", function (event) {
          var target = event.target;
          if (!target) {
            return;
          }
          var tag = target.tagName;
          var isCheckbox = tag === "INPUT" && target.type === "checkbox";
          if (tag === "SELECT" || isCheckbox) {
            form.submit();
          }
        });
      })(forms[i]);
    }
  }

  /*
   * Copy a freshly issued set of recovery codes.
   *
   * The button is rendered hidden and revealed here, so a browser without the
   * clipboard interface never shows a control that would do nothing. The codes
   * are on the page either way, and selecting them by hand works.
   */
  function wireCopy(root) {
    if (!navigator.clipboard || !navigator.clipboard.writeText) {
      return;
    }

    var buttons = root.querySelectorAll("button[data-copy-from]");
    for (var i = 0; i < buttons.length; i++) {
      (function (button) {
        var source = document.getElementById(button.getAttribute("data-copy-from"));
        if (!source) {
          return;
        }
        button.hidden = false;

        var original = button.textContent;
        button.addEventListener("click", function () {
          var items = source.querySelectorAll("li");
          var lines = [];
          for (var j = 0; j < items.length; j++) {
            lines.push(items[j].textContent.trim());
          }
          navigator.clipboard.writeText(lines.join("\n")).then(
            function () {
              button.textContent = "Copied";
              window.setTimeout(function () {
                button.textContent = original;
              }, 2000);
            },
            function () {
              button.textContent = "Could not copy, select the codes instead";
            }
          );
        });
      })(buttons[i]);
    }
  }

  /*
   * WebAuthn is only usable over a secure context, and only where the browser
   * implements it. Asking both questions in one place means the two controls
   * below cannot disagree about whether to appear.
   */
  function passkeysUsable() {
    return !!(window.PublicKeyCredential && navigator.credentials &&
      navigator.credentials.create && navigator.credentials.get &&
      window.isSecureContext);
  }

  /*
   * base64url, which is what the service speaks in both directions.
   *
   * The options carry the challenge, the user handle and every credential
   * identifier as base64url text, because that is what survives JSON; the
   * browser wants ArrayBuffers. The response travels back the same way.
   */
  function decode(value) {
    var padded = value.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4 !== 0) {
      padded += "=";
    }
    var raw = window.atob(padded);
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) {
      bytes[i] = raw.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function encode(buffer) {
    var bytes = new Uint8Array(buffer);
    var raw = "";
    for (var i = 0; i < bytes.length; i++) {
      raw += String.fromCharCode(bytes[i]);
    }
    return window.btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  /*
   * Post a form body and read the JSON answer.
   *
   * The body is form encoded rather than JSON so that the authenticated routes
   * carry the same hidden request token every other form on this interface
   * carries, and are checked by the same server-side comparison. A refusal that
   * is not JSON, which is what the request-token check renders, is reported as
   * an expired page rather than as a parse failure nobody can act on.
   */
  function post(path, fields) {
    var body = new URLSearchParams();
    for (var key in fields) {
      if (Object.prototype.hasOwnProperty.call(fields, key)) {
        body.append(key, fields[key]);
      }
    }
    return window.fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString()
    }).then(function (response) {
      return response.json().then(
        function (doc) {
          if (!response.ok) {
            throw new Error(doc && doc.problem ? doc.problem : "That did not work.");
          }
          return doc;
        },
        function () {
          throw new Error("This page has expired. Reload it and try again.");
        }
      );
    });
  }

  function showProblem(element, message) {
    if (!element) {
      return;
    }
    element.textContent = message;
    element.hidden = false;
  }

  function hideProblem(element) {
    if (element) {
      element.hidden = true;
    }
  }

  /*
   * Sign in with a passkey.
   *
   * The service chooses where to go next and always names a fixed path, so the
   * page never navigates to somewhere a response could be made to point.
   */
  function wirePasskeySignIn() {
    var panel = document.getElementById("passkey-sign-in");
    var button = document.getElementById("passkey-sign-in-button");
    var problem = document.getElementById("passkey-sign-in-problem");
    if (!panel || !button || !passkeysUsable()) {
      return;
    }
    panel.hidden = false;

    button.addEventListener("click", function () {
      hideProblem(problem);
      button.disabled = true;

      post("/admin/sign-in/passkey/begin", {}).then(function (begun) {
        var options = begun.options.publicKey;
        options.challenge = decode(options.challenge);
        if (options.allowCredentials) {
          for (var i = 0; i < options.allowCredentials.length; i++) {
            options.allowCredentials[i].id = decode(options.allowCredentials[i].id);
          }
        }
        return navigator.credentials.get({ publicKey: options }).then(function (assertion) {
          return post("/admin/sign-in/passkey/complete", {
            challenge_id: begun.challenge_id,
            credential: JSON.stringify({
              id: assertion.id,
              rawId: encode(assertion.rawId),
              type: assertion.type,
              response: {
                clientDataJSON: encode(assertion.response.clientDataJSON),
                authenticatorData: encode(assertion.response.authenticatorData),
                signature: encode(assertion.response.signature),
                userHandle: assertion.response.userHandle ? encode(assertion.response.userHandle) : ""
              }
            })
          });
        });
      }).then(function (done) {
        window.location.assign(done.redirect);
      }).catch(function (err) {
        button.disabled = false;
        showProblem(problem, err && err.message ? err.message : "That passkey was not accepted.");
      });
    });
  }

  /*
   * Add a passkey to the administrator sign-in already in use.
   *
   * The request token is read from the panel rather than written here, for the
   * reason the confirmation wording is: it belongs beside the control it
   * protects, and a second control cannot inherit the wrong one.
   */
  function wirePasskeyEnrolment() {
    var panel = document.getElementById("passkey-enrol");
    var button = document.getElementById("passkey-enrol-button");
    var problem = document.getElementById("passkey-enrol-problem");
    var label = document.getElementById("passkey-label");
    if (!panel || !button || !passkeysUsable()) {
      return;
    }
    var csrf = panel.getAttribute("data-csrf") || "";
    panel.hidden = false;

    button.addEventListener("click", function () {
      hideProblem(problem);
      button.disabled = true;

      post("/admin/passkeys/begin", { csrf_token: csrf }).then(function (begun) {
        var options = begun.options.publicKey;
        options.challenge = decode(options.challenge);
        options.user.id = decode(options.user.id);
        if (options.excludeCredentials) {
          for (var i = 0; i < options.excludeCredentials.length; i++) {
            options.excludeCredentials[i].id = decode(options.excludeCredentials[i].id);
          }
        }
        return navigator.credentials.create({ publicKey: options }).then(function (created) {
          var transports = [];
          if (created.response.getTransports) {
            transports = created.response.getTransports() || [];
          }
          return post("/admin/passkeys/complete", {
            csrf_token: csrf,
            challenge_id: begun.challenge_id,
            label: label ? label.value : "",
            credential: JSON.stringify({
              id: created.id,
              rawId: encode(created.rawId),
              type: created.type,
              response: {
                clientDataJSON: encode(created.response.clientDataJSON),
                attestationObject: encode(created.response.attestationObject),
                transports: transports
              }
            })
          });
        });
      }).then(function (done) {
        window.location.assign(done.redirect);
      }).catch(function (err) {
        button.disabled = false;
        showProblem(problem, err && err.message ? err.message : "That passkey was not accepted.");
      });
    });
  }

  function start() {
    wireConfirmations(document);
    wireFilters(document);
    wireCopy(document);
    wirePasskeySignIn();
    wirePasskeyEnrolment();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
