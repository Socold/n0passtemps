/*
 * Administration interface behaviour.
 *
 * Three additions, and nothing else. Every screen works with this file blocked
 * or disabled: the confirmations are a second thought before something final,
 * the filter submission saves a click on a form that already has a button, and
 * the copy control is a convenience beside text the operator can select by hand.
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

  function start() {
    wireConfirmations(document);
    wireFilters(document);
    wireCopy(document);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
