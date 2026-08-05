//! The item editor — create, edit, generate.
//!
//! Kept apart from `app.rs` with its own message type so the form's state
//! machine can be reasoned about (and tested) on its own; `app` maps
//! [`EditorMessage`] into its own message and only handles the two outcomes
//! the editor reports back.

use cosmic::iced::{Alignment, Length};
use cosmic::prelude::*;
use cosmic::widget;
use passman_core::{
    generator::{self, PasswordRecipe},
    model::{Field, FieldKind, Item, ItemKind, field_names},
};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub enum EditorMessage {
    Label(String),
    Kind(usize),
    Secret(String),
    ToggleSecretReveal,
    Generate,
    LengthChanged(f64),
    ToggleSymbols(bool),
    FieldName(usize, String),
    FieldValue(usize, String),
    FieldKindChanged(usize, usize),
    ToggleFieldReveal(usize),
    AddField,
    RemoveField(usize),
    Save,
    Cancel,
}

/// What the editor wants the application to do next.
pub enum Outcome {
    /// Keep editing.
    Continue,
    /// Commit `item`; `id` is `None` when it is a new item.
    Save { id: Option<Uuid>, item: Box<Item> },
    Cancel,
}

#[derive(Debug, Clone)]
pub struct EditField {
    pub name: String,
    pub kind: FieldKind,
    pub value: String,
    pub revealed: bool,
}

pub struct Editor {
    /// `None` while creating a new item.
    pub id: Option<Uuid>,
    pub label: String,
    pub kind_index: usize,
    pub secret: String,
    pub secret_revealed: bool,
    pub fields: Vec<EditField>,
    pub generator_length: f64,
    pub generator_symbols: bool,
    /// Attributes are preserved verbatim; other applications search on them,
    /// so the editor must not drop what it does not display.
    pub attributes: std::collections::BTreeMap<String, String>,
    pub favorite: bool,
    pub error: Option<String>,
}

impl Editor {
    /// A blank editor pre-seeded with the fields that kind usually carries.
    pub fn new(kind: ItemKind) -> Self {
        let kind_index = ItemKind::ALL.iter().position(|k| *k == kind).unwrap_or(0);
        let fields = match kind {
            ItemKind::Login => vec![
                EditField {
                    name: field_names::USERNAME.into(),
                    kind: FieldKind::Text,
                    value: String::new(),
                    revealed: false,
                },
                EditField {
                    name: field_names::URL.into(),
                    kind: FieldKind::Url,
                    value: String::new(),
                    revealed: false,
                },
            ],
            _ => Vec::new(),
        };

        Self {
            id: None,
            label: String::new(),
            kind_index,
            secret: String::new(),
            secret_revealed: false,
            fields,
            generator_length: 20.0,
            generator_symbols: true,
            attributes: Default::default(),
            favorite: false,
            error: None,
        }
    }

    /// An editor populated from an existing item.
    pub fn from_item(item: &Item) -> Self {
        Self {
            id: Some(item.id),
            label: item.label.clone(),
            kind_index: ItemKind::ALL
                .iter()
                .position(|k| *k == item.kind)
                .unwrap_or(0),
            secret: item.secret.expose().to_owned(),
            secret_revealed: false,
            fields: item
                .fields
                .iter()
                .map(|f| EditField {
                    name: f.name.clone(),
                    kind: f.kind,
                    value: f.value.expose().to_owned(),
                    revealed: false,
                })
                .collect(),
            generator_length: 20.0,
            generator_symbols: true,
            attributes: item.attributes.clone(),
            favorite: item.favorite,
            error: None,
        }
    }

    pub fn kind(&self) -> ItemKind {
        ItemKind::ALL
            .get(self.kind_index)
            .copied()
            .unwrap_or(ItemKind::Login)
    }

    pub fn is_new(&self) -> bool {
        self.id.is_none()
    }

    fn recipe(&self) -> PasswordRecipe {
        PasswordRecipe {
            length: self.generator_length as usize,
            symbols: self.generator_symbols,
            ..Default::default()
        }
    }

    /// Build the item this form describes.
    fn to_item(&self) -> Result<Item, String> {
        if self.label.trim().is_empty() {
            return Err("Give the item a name.".into());
        }
        if self.fields.iter().any(|f| f.name.trim().is_empty()) {
            return Err("Every field needs a name.".into());
        }

        let mut item = Item::new(self.kind(), self.label.trim());
        // Preserve identity so an edit updates rather than replaces; other
        // applications may hold this item's D-Bus path.
        if let Some(id) = self.id {
            item.id = id;
        }
        item.secret = self.secret.clone().into();
        item.attributes = self.attributes.clone();
        item.favorite = self.favorite;
        item.fields = self
            .fields
            .iter()
            .filter(|f| !f.name.trim().is_empty())
            .map(|f| Field::new(f.name.trim(), f.kind, f.value.clone()))
            .collect();
        Ok(item)
    }

    pub fn update(&mut self, message: EditorMessage) -> Outcome {
        match message {
            EditorMessage::Label(v) => {
                self.label = v;
                self.error = None;
            }
            EditorMessage::Kind(i) => self.kind_index = i,
            EditorMessage::Secret(v) => self.secret = v,
            EditorMessage::ToggleSecretReveal => {
                self.secret_revealed = !self.secret_revealed;
            }
            EditorMessage::LengthChanged(v) => self.generator_length = v,
            EditorMessage::ToggleSymbols(v) => self.generator_symbols = v,

            EditorMessage::Generate => match generator::password(&self.recipe()) {
                Ok(pw) => {
                    self.secret = pw.expose().to_owned();
                    // Reveal it: a password you cannot see is one you cannot
                    // check against a site's composition rules.
                    self.secret_revealed = true;
                    self.error = None;
                }
                Err(e) => self.error = Some(e.to_string()),
            },

            EditorMessage::FieldName(i, v) => {
                if let Some(f) = self.fields.get_mut(i) {
                    f.name = v;
                }
            }
            EditorMessage::FieldValue(i, v) => {
                if let Some(f) = self.fields.get_mut(i) {
                    f.value = v;
                }
            }
            EditorMessage::FieldKindChanged(i, k) => {
                if let (Some(f), Some(kind)) = (self.fields.get_mut(i), FieldKind::ALL.get(k)) {
                    f.kind = *kind;
                }
            }
            EditorMessage::ToggleFieldReveal(i) => {
                if let Some(f) = self.fields.get_mut(i) {
                    f.revealed = !f.revealed;
                }
            }
            EditorMessage::AddField => self.fields.push(EditField {
                name: String::new(),
                kind: FieldKind::Text,
                value: String::new(),
                revealed: true,
            }),
            EditorMessage::RemoveField(i) => {
                if i < self.fields.len() {
                    self.fields.remove(i);
                }
            }

            EditorMessage::Save => match self.to_item() {
                Ok(item) => {
                    return Outcome::Save { id: self.id, item: Box::new(item) };
                }
                Err(e) => self.error = Some(e),
            },
            EditorMessage::Cancel => return Outcome::Cancel,
        }
        Outcome::Continue
    }

    pub fn view(&self) -> Element<'_, EditorMessage> {
        let spacing = cosmic::theme::spacing();
        let kind_labels: Vec<&str> = ItemKind::ALL.iter().map(|k| k.label()).collect();
        let field_kind_labels: Vec<&str> = FieldKind::ALL.iter().map(|k| k.label()).collect();

        let mut form = widget::column::with_capacity(10).spacing(spacing.space_s);

        form = form.push(widget::text::title3(if self.is_new() {
            "New item"
        } else {
            "Edit item"
        }));

        if let Some(error) = &self.error {
            form = form.push(widget::text::body(error.clone()).class(cosmic::theme::Text::Color(
                cosmic::theme::active().cosmic().destructive_color().into(),
            )));
        }

        form = form
            .push(widget::text::caption_heading("Name"))
            .push(
                widget::text_input("e.g. GitHub", &self.label)
                    .on_input(EditorMessage::Label)
                    .on_submit(|_| EditorMessage::Save),
            )
            .push(widget::text::caption_heading("Type"))
            .push(widget::dropdown(
                kind_labels,
                Some(self.kind_index),
                EditorMessage::Kind,
            ));

        // -- primary secret + generator ------------------------------------
        form = form.push(widget::text::caption_heading("Password / secret")).push(
            widget::row::with_capacity(2)
                .spacing(spacing.space_xxs)
                .align_y(Alignment::Center)
                .push(
                    widget::text_input::secure_input(
                        "",
                        &self.secret,
                        Some(EditorMessage::ToggleSecretReveal),
                        !self.secret_revealed,
                    )
                    .on_input(EditorMessage::Secret)
                    .width(Length::Fill),
                )
                .push(widget::button::standard("Generate").on_press(EditorMessage::Generate)),
        );

        let recipe = self.recipe();
        form = form.push(
            widget::row::with_capacity(3)
                .spacing(spacing.space_s)
                .align_y(Alignment::Center)
                .push(widget::text::caption(format!(
                    "{} chars · ~{:.0} bits",
                    recipe.length,
                    recipe.entropy_bits()
                )))
                .push(
                    widget::slider(8.0..=64.0, self.generator_length, EditorMessage::LengthChanged)
                        .step(1.0)
                        .width(Length::Fill),
                )
                .push(
                    widget::toggler(self.generator_symbols)
                        .label("Symbols".to_string())
                        .on_toggle(EditorMessage::ToggleSymbols),
                ),
        );

        // -- extra fields ---------------------------------------------------
        form = form.push(widget::divider::horizontal::default());
        form = form.push(widget::text::caption_heading("Fields"));

        for (i, field) in self.fields.iter().enumerate() {
            let value_input: Element<'_, EditorMessage> = if field.kind.is_sensitive() {
                widget::text_input::secure_input(
                    "Value",
                    &field.value,
                    Some(EditorMessage::ToggleFieldReveal(i)),
                    !field.revealed,
                )
                .on_input(move |v| EditorMessage::FieldValue(i, v))
                .width(Length::Fill)
                .into()
            } else {
                widget::text_input("Value", &field.value)
                    .on_input(move |v| EditorMessage::FieldValue(i, v))
                    .width(Length::Fill)
                    .into()
            };

            let kind_index = FieldKind::ALL
                .iter()
                .position(|k| *k == field.kind)
                .unwrap_or(0);

            form = form.push(
                widget::column::with_capacity(2)
                    .spacing(spacing.space_xxs)
                    .push(
                        widget::row::with_capacity(3)
                            .spacing(spacing.space_xxs)
                            .align_y(Alignment::Center)
                            .push(
                                widget::text_input("Name", &field.name)
                                    .on_input(move |v| EditorMessage::FieldName(i, v))
                                    .width(Length::FillPortion(2)),
                            )
                            .push(
                                widget::dropdown(
                                    field_kind_labels.clone(),
                                    Some(kind_index),
                                    move |k| EditorMessage::FieldKindChanged(i, k),
                                )
                                .width(Length::FillPortion(2)),
                            )
                            .push(
                                widget::button::destructive("Remove")
                                    .on_press(EditorMessage::RemoveField(i)),
                            ),
                    )
                    .push(value_input),
            );
        }

        form = form.push(widget::button::standard("Add field").on_press(EditorMessage::AddField));

        // Attributes are carried through untouched; say so rather than
        // silently keeping hidden state.
        if !self.attributes.is_empty() {
            form = form.push(widget::text::caption(format!(
                "{} Secret Service attribute(s) will be preserved",
                self.attributes.len()
            )));
        }

        form = form.push(widget::divider::horizontal::default()).push(
            widget::row::with_capacity(2)
                .spacing(spacing.space_xs)
                .push(widget::button::suggested("Save").on_press(EditorMessage::Save))
                .push(widget::button::standard("Cancel").on_press(EditorMessage::Cancel)),
        );

        widget::scrollable(widget::container(form).padding(spacing.space_s))
            .height(Length::Fill)
            .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saved(editor: &mut Editor) -> Option<Item> {
        match editor.update(EditorMessage::Save) {
            Outcome::Save { item, .. } => Some(*item),
            _ => None,
        }
    }

    #[test]
    fn a_new_login_starts_with_the_usual_fields() {
        let e = Editor::new(ItemKind::Login);
        assert!(e.is_new());
        let names: Vec<&str> = e.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec![field_names::USERNAME, field_names::URL]);
    }

    #[test]
    fn saving_without_a_name_is_refused() {
        let mut e = Editor::new(ItemKind::Login);
        assert!(saved(&mut e).is_none());
        assert!(e.error.is_some(), "no error shown for a nameless item");
    }

    #[test]
    fn saving_with_an_unnamed_field_is_refused() {
        let mut e = Editor::new(ItemKind::Note);
        e.update(EditorMessage::Label("Note".into()));
        e.update(EditorMessage::AddField);
        e.update(EditorMessage::FieldValue(0, "orphan".into()));
        assert!(saved(&mut e).is_none());
    }

    #[test]
    fn round_trips_an_existing_item_without_losing_anything() {
        let original = Item::new(ItemKind::Login, "GitHub")
            .with_secret("hunter2")
            .with_field(Field::text(field_names::USERNAME, "ada"))
            .with_attribute("service", "github.com");

        let mut e = Editor::from_item(&original);
        assert!(!e.is_new());
        let item = saved(&mut e).expect("a populated editor should save");

        assert_eq!(item.id, original.id, "editing must not change the item id");
        assert_eq!(item.label, "GitHub");
        assert_eq!(item.secret.expose(), "hunter2");
        assert_eq!(item.field_value(field_names::USERNAME), Some("ada"));
        assert_eq!(
            item.attributes.get("service").map(String::as_str),
            Some("github.com"),
            "Secret Service attributes were dropped"
        );
    }

    #[test]
    fn generate_fills_the_secret_and_respects_the_recipe() {
        let mut e = Editor::new(ItemKind::Login);
        e.update(EditorMessage::LengthChanged(32.0));
        e.update(EditorMessage::ToggleSymbols(false));
        e.update(EditorMessage::Generate);

        assert_eq!(e.secret.chars().count(), 32);
        assert!(e.secret.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(e.secret_revealed, "generated password stayed masked");
    }

    #[test]
    fn fields_can_be_added_removed_and_retyped() {
        let mut e = Editor::new(ItemKind::Note);
        e.update(EditorMessage::Label("N".into()));
        let before = e.fields.len();

        e.update(EditorMessage::AddField);
        e.update(EditorMessage::FieldName(before, "token".into()));
        e.update(EditorMessage::FieldValue(before, "abc".into()));
        let secret_index = FieldKind::ALL
            .iter()
            .position(|k| *k == FieldKind::Secret)
            .unwrap();
        e.update(EditorMessage::FieldKindChanged(before, secret_index));
        assert_eq!(e.fields[before].kind, FieldKind::Secret);

        let item = saved(&mut e).unwrap();
        assert_eq!(item.field_value("token"), Some("abc"));

        e.update(EditorMessage::RemoveField(before));
        assert_eq!(e.fields.len(), before);
    }

    #[test]
    fn out_of_range_indices_are_ignored_rather_than_panicking() {
        let mut e = Editor::new(ItemKind::Note);
        e.update(EditorMessage::FieldValue(99, "x".into()));
        e.update(EditorMessage::RemoveField(99));
        e.update(EditorMessage::FieldKindChanged(99, 99));
        e.update(EditorMessage::Kind(99));
        // A nonsense kind index falls back to a sane default.
        assert_eq!(e.kind(), ItemKind::Login);
    }

    #[test]
    fn cancel_reports_cancel() {
        let mut e = Editor::new(ItemKind::Login);
        assert!(matches!(e.update(EditorMessage::Cancel), Outcome::Cancel));
    }

    #[test]
    fn whitespace_in_names_is_trimmed() {
        let mut e = Editor::new(ItemKind::Note);
        e.update(EditorMessage::Label("  Padded  ".into()));
        let item = saved(&mut e).unwrap();
        assert_eq!(item.label, "Padded");
    }
}
