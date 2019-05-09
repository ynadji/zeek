// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <iosource/Packet.h>
#include "Tag.h"
#include "Defines.h"
#include "Manager.h"

namespace llanalyzer {

class Analyzer {
public:
	/**
	 * Constructor.
	 *
	 * @param name The name for the type of analyzer. The name must match
	 * the one the corresponding Component registers.
	 */
	explicit Analyzer(std::string name);

	/**
	 * Constructor.
	 *
	 * @param tag The tag for the type of analyzer. The tag must map to
	 * the name the corresponding Component registers.
	 */
	explicit Analyzer(const Tag& tag);

	/**
	 * Destructor.
	 */
	virtual ~Analyzer();

	/**
	 * Returns the tag associated with the analyzer's type.
	 */
	const Tag GetAnalyzerTag() const;

	/**
	 * Returns a textual description of the analyzer's type. This is
	 * what's passed to the constructor and usally corresponds to the
	 * protocol name, e.g., "ARP".
	 */
	const char* GetAnalyzerName() const;

	/**
	 * Returns true if this analyzer's type matches the name passes in.
	 * This is shortcut for comparing GetAnalyzerName() with the given
	 * name.
	 *
	 * @param name The name to check.
	 */
	bool IsAnalyzer(const char* name);

	virtual identifier_t getIdentifier(Packet *packet) = 0;
	virtual void analyze(Packet *packet) = 0;

protected:
	friend class Manager;

private:
    Tag tag;

    void init(const Tag& tag);
};

} // llanalyzer namespace end