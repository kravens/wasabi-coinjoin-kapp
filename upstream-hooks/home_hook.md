# Upstream hook for the official Krux `home.py`

One line added to the Sign submenu builder in
`src/krux/pages/home_pages/home.py`, plus the import. This is the only core
change needed; everything else lives in `krux/extensions/`.

```diff
 from ...krux_settings import t
+from krux import extensions
 ...
     def sign(self):
         """Handler for the 'sign' menu item"""
         submenu = Menu(
             self.ctx,
             [
                 ("PSBT", self.sign_psbt),
                 (t("Message"), self.sign_message),
-            ],
+            ]
+            + extensions.sign_menu_entries(self.ctx),
         )
         submenu.run_loop()
         return MENU_CONTINUE
```

`extensions.sign_menu_entries` returns `[]` when no extension is installed, so
this is inert on a stock build. Menu entries are `(label, handler)` tuples,
matching the existing `Menu` item shape.
