%extern{
#include "zeek/ZeekString.h"
%}

refine flow SIP_Flow += {

	%member{
		int content_length;
		bool build_headers;
		std::vector<zeek::ValPtr> headers;
	%}

	%init{
		content_length = 0;
		build_headers = bool(sip_all_headers);
	%}

	function get_content_length(): int
		%{
		return content_length;
		%}

	function proc_sip_request(junk: bytestring, method: bytestring, uri: bytestring, vers: SIP_Version): bool
		%{
		if ( junk.length() )
			{
			zeek::String zs{junk.begin(), junk.length(), false};
			auto addl = zs.Render();
			connection()->zeek_analyzer()->Weird("sip_junk_before_request", addl);
			delete [] addl;
			}

		if ( sip_request )
			{
			zeek::BifEvent::enqueue_sip_request(connection()->zeek_analyzer(), connection()->zeek_analyzer()->Conn(),
						       to_stringval(method), to_stringval(uri),
						       to_stringval(${vers.vers_str}));
			}

		proc_sip_message_begin();

		return true;
		%}

	function proc_sip_reply(vers: SIP_Version, code: int, reason: bytestring): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();
		if ( sip_reply )
			{
			zeek::BifEvent::enqueue_sip_reply(connection()->zeek_analyzer(), connection()->zeek_analyzer()->Conn(),
						     to_stringval(${vers.vers_str}), code, to_stringval(reason));
			}

		proc_sip_message_begin();

		return true;
		%}

	function proc_sip_header(name: bytestring, value: bytestring): bool
		%{
		if ( name == "Content-Length" || name == "L" )
			content_length = bytestring_to_int(value, 10);

		if ( sip_header )
			{
			auto nameval = to_stringval(name);
			nameval->ToUpper();
			zeek::BifEvent::enqueue_sip_header(connection()->zeek_analyzer(), connection()->zeek_analyzer()->Conn(),
						      is_orig(), std::move(nameval), to_stringval(value));
			}

		if ( build_headers )
			{
			headers.emplace_back(zeek::AdoptRef{}, build_sip_header_val(name, value));
			}

		return true;
		%}

	function build_sip_headers_val(): ZeekVal
		%{
		static auto mime_header_list = zeek::id::find_type<zeek::TableType>("mime_header_list");
		auto* t = new zeek::TableVal(mime_header_list);

		for ( unsigned int i = 0; i < headers.size(); ++i )
			{ // index starting from 1
			auto index = zeek::val_mgr->Count(i + 1);
			t->Assign(std::move(index), std::move(headers[i]));
			}

		return t;
		%}

	function gen_sip_all_headers(): void
		%{
		if ( sip_all_headers )
			{
			zeek::BifEvent::enqueue_sip_all_headers(connection()->zeek_analyzer(), connection()->zeek_analyzer()->Conn(),
							   is_orig(), {zeek::AdoptRef{}, build_sip_headers_val()});
			}

		headers.clear();
		%}

	function proc_sip_end_of_headers(headers: SIP_Headers): bool
		%{
		if ( build_headers )
			{
			gen_sip_all_headers();
			}

		return true;
		%}

	function build_sip_header_val(name: const_bytestring, value: const_bytestring): ZeekVal
		%{
		static auto mime_header_rec = zeek::id::find_type<zeek::RecordType>("mime_header_rec");
		auto* header_record = new zeek::RecordVal(mime_header_rec);
		zeek::StringValPtr name_val;

		if ( name.length() > 0 )
			{
			// Make it all uppercase.
			name_val = zeek::make_intrusive<zeek::StringVal>(name.length(), (const char*) name.begin());
			name_val->ToUpper();
			}
		else
			{
			name_val = zeek::val_mgr->EmptyString();
			}

		header_record->Assign(0, name_val);
		header_record->Assign(1, to_stringval(value));

		return header_record;
		%}

	function proc_sip_message_begin(): void
		%{
		if ( sip_begin_entity )
			{
			zeek::BifEvent::enqueue_sip_begin_entity(connection()->zeek_analyzer(), connection()->zeek_analyzer()->Conn(), is_orig());
			}
		%}

	function proc_sip_message_done(pdu: SIP_PDU): bool
		%{
		if ( sip_end_entity )
			{
			zeek::BifEvent::enqueue_sip_end_entity(connection()->zeek_analyzer(), connection()->zeek_analyzer()->Conn(), is_orig());
			}

		return true;
		%}

};

refine typeattr SIP_RequestLine += &let {
       proc: bool = $context.flow.proc_sip_request(junk, method, uri, version);
};

refine typeattr SIP_ReplyLine += &let {
       proc: bool = $context.flow.proc_sip_reply(version, status.stat_num, reason);
};

refine typeattr SIP_Header += &let {
       proc: bool = $context.flow.proc_sip_header(name, value);
};

refine typeattr SIP_Headers += &let {
       proc: bool = $context.flow.proc_sip_end_of_headers(this);
};

refine typeattr SIP_PDU += &let {
       proc: bool = $context.flow.proc_sip_message_done(this);
};
