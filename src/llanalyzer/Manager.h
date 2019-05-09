// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_MANAGER_H
#define ANALYZER_MANAGER_H

#include <queue>
#include <vector>

#include "Tag.h"
#include "Analyzer.h"
#include "Component.h"
#include "AnalyzerSet.h"
#include "plugin/ComponentManager.h"

#include "../Dict.h"
#include "../net_util.h"

namespace llanalyzer {
class AnalyzerSet;

class Manager : public plugin::ComponentManager<Tag, Component> {
public:
	/**
	 * Constructor.
	 */
	Manager();

	/**
	 * Destructor.
	 */
	~Manager();

	/**
	 * First-stage initializion of the manager. This is called early on
	 * during Bro's initialization, before any scripts are processed.
	 */
	void InitPreScript();

	/**
	 * Second-stage initialization of the manager. This is called late
	 * during Bro's initialization after any scripts are processed.
	 */
	void InitPostScript();

    /**
     * Finished the manager's operations.
     */
    void Done();

    /**
     * Dumps out the state of all registered analyzers to the \c analyzer
     * debug stream. Should be called only after any \c zeek_init events
     * have executed to ensure that any of their changes are applied.
     */
    void DumpDebug(); // Called after zeek_init() events.

	/**
	 * Enables an analyzer type. Only enabled analyzers will be
	 * instantiated for new connections.
	 *
	 * @param tag The analyzer's tag.
	 *
	 * @return True if successful.
	 */
	bool EnableAnalyzer(const Tag& tag);

	/**
	 * Enables an analyzer type. Only enabled analyzers will be
	 * instantiated for new connections.
	 *
	 * @param tag The analyzer's tag as an enum of script type \c
	 * Analyzer::Tag.
	 *
	 * @return True if successful.
	 */
	bool EnableAnalyzer(EnumVal* tag);

	/**
	 * Enables an analyzer type. Disabled analyzers will not be
	 * instantiated for new connections.
	 *
	 * @param tag The analyzer's tag.
	 *
	 * @return True if successful.
	 */
	bool DisableAnalyzer(const Tag& tag);

	/**
	 * Disables an analyzer type. Disabled analyzers will not be
	 * instantiated for new connections.
	 *
	 * @param tag The analyzer's tag as an enum of script type \c
	 * Analyzer::Tag.
	 *
	 * @return True if successful.
	 */
	bool DisableAnalyzer(EnumVal* tag);

	/**
	 * Disables all currently registered analyzers.
	 */
	void DisableAllAnalyzers();

	/**
	 * Returns the tag associated with an analyer name, or the tag
	 * associated with an error if no such analyzer exists.
	 *
	 * @param name The canonical analyzer name to check.
	 */
	Tag GetAnalyzerTag(const char* name);

	/**
	 * Returns true if an analyzer is enabled.
	 *
	 * @param tag The analyzer's tag.
	 */
	bool IsEnabled(Tag tag);

	/**
	 * Returns true if an analyzer is enabled.
	 *
	 * @param tag The analyzer's tag as an enum of script type \c
	 * Analyzer::Tag.
	 */
	bool IsEnabled(EnumVal* tag);

	/**
	 * Instantiates a new analyzer instance.
	 *
	 * @param tag The analyzer's tag.
	 *
	 * @return The new analyzer instance. Returns
	 * null if tag is invalid, the requested analyzer is disabled, or the
	 * analyzer can't be instantiated.
	 */
	Analyzer* InstantiateAnalyzer(const Tag& tag);

	/**
	 * Instantiates a new analyzer.
	 *
	 * @param name The name of the analyzer.
	 *
	 * @return The new analyzer instance. Returns
	 * null if the name is not known or if the requested analyzer that is
	 * disabled.
	 */
	Analyzer* InstantiateAnalyzer(const std::string& name);

	void processPacket(Packet* packet);

private:
    AnalyzerSet* analyzerSet;
};

}

extern llanalyzer::Manager* llanalyzer_mgr;

#endif
