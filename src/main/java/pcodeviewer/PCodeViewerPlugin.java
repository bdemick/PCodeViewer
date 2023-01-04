/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package pcodeviewer;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * This plugin provides a view into the current function's PCode.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = PCodeViewerPlugin.PLUGIN_NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Explore different levels of PCode for a function.",
	description = "PCode view creates a PCode-specific view to separately "
			+ "render the different levels of PCode for a function."
)
//@formatter:on
public class PCodeViewerPlugin extends ProgramPlugin {
	public static final String PLUGIN_NAME = "PCodeViewer";

	PCodeProvider provider;

	/**
	 * PCodeViewerPlugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public PCodeViewerPlugin(PluginTool tool) {
		super(tool);

		String pluginName = getName();
		provider = new PCodeProvider(this, pluginName);

		// TODO: Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
	}
	
	@Override
	protected void programDeactivated(Program program) {
		provider.clear();
	}
	
	@Override
	protected void locationChanged(ProgramLocation loc) {
		provider.locationChanged(currentProgram, loc);
	}

}
