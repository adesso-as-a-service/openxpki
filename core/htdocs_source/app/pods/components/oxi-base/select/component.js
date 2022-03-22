import Component from '@glimmer/component';
import { action } from "@ember/object";
import { debug } from '@ember/debug';
/**
 * Shows a drop-down list of options.
 *
 * ```html
 * <OxiBase::Select @list={{data.keys}} @selected={{data.name}} @onChange={{myFunc}} @onInsert={{otherFunc}}/>
 * ```
 *
 * @param { array } list - List of hashes defining the options.
 * Each hash is expected to have these keys:
 * ```javascript
 * [
 *     { value: 1, label: "Major" },
 *     { value: 2, label: "Tom" },
 * ]
 * ```
 * @param { string } selected - currently selected value
 * @param { callback } onChange - called if a selection was made.
 * It gets passed two arguments: *value* and *label* of the selected item.
 * The callback is also called initially to set the value of the first list item.
 * @module component/oxi-base/select
 */
export default class OxiSelectComponent extends Component {
    @action
    listChanged(event) {
        this.notifyOnChange(event.target.selectedIndex);
    }

    // initially trigger the onChange event to handle the case
    // when the calling code has no "current selection" defined.
    @action
    startup(element) {
        if (this.args.onInsert) this.args.onInsert(element);
        this.notifyOnChange(element.selectedIndex);
    }

    notifyOnChange(index) {
        if (index === -1) { return } // there might be no options on page initialization, before field is hidden by a "partial" request
        let item = this.args.list[index];
        debug(`oxi-select: notifyOnChange (value="${item.value}", label="${item.label}")`);
        if (typeof this.args.onChange !== "function") {
            /* eslint-disable-next-line no-console */
            console.error("<OxiBase::Select>: Wrong type parameter type for @onChange. Expected: function, given: " + (typeof this.args.onChange));
            return;
        }
        this.args.onChange(item.value, item.label);
    }
}
