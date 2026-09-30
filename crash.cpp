
namespace
{
	struct server_lagger_profile_t
	{
		std::uint32_t messages_per_datagram;
		int maximum_datagrams_per_tick;
		std::size_t packet_offsets_per_message;
	};

	constexpr server_lagger_profile_t kModeOneProfile = { 65, 14, 1475 };
	constexpr server_lagger_profile_t kModeTwoProfile = { 6, 119, 16320 };

	struct bit_read_t
	{
		const void* data;
		std::int32_t data_bytes;
		std::int32_t data_bits;
		std::int32_t current_bit;
		std::uint32_t reserved;
		const char* debug_name;
		bool overflow;
		bool initialized;
		bool dword_safe;
		std::uint8_t tail[ 5 ];
	};

	static_assert( sizeof( bit_read_t ) == 0x28 );
	static_assert( offsetof( bit_read_t, overflow ) == 0x20 );

	struct voice_payload_t
	{
		std::array< std::uint8_t, 10 + 16320 + 1 + sizeof( std::uint64_t ) + 1 + 5 > bytes = { };
		std::size_t size = { };
	};

	struct voice_runtime_t
	{
		void* network_client = { };
		int tick = -1;
	};

	const server_lagger_profile_t& selected_server_lagger_profile( )
	{
		return config::misc_server_lagger_mode == 1 ? kModeTwoProfile : kModeOneProfile;
	}

	std::mt19937_64 g_voice_xuid_generator { std::random_device { }( ) };

	void append_varint( std::uint32_t value, std::vector< std::uint8_t >& output )
	{
		do
		{
			std::uint8_t byte = static_cast< std::uint8_t >( value & 0x7Fu );
			value >>= 7u;
			if ( value )
				byte |= 0x80u;
			output.push_back( byte );
		} while ( value );
	}

	voice_payload_t make_voice_payload( const server_lagger_profile_t& profile, std::uint64_t xuid, std::uint32_t tick )
	{
		const std::size_t audio_payload_bytes = 2 + 2 + 3 + profile.packet_offsets_per_message;
		const std::array< std::uint8_t, 10 > prefix = {
			0x0A,
			static_cast< std::uint8_t >( ( audio_payload_bytes & 0x7F ) | 0x80 ),
			static_cast< std::uint8_t >( audio_payload_bytes >> 7u ),
			0x08,
			0x02,
			0x12,
			0x00,
			0x42,
			static_cast< std::uint8_t >( ( profile.packet_offsets_per_message & 0x7F ) | 0x80 ),
			static_cast< std::uint8_t >( profile.packet_offsets_per_message >> 7u ),
		};

		voice_payload_t payload;
		std::copy( prefix.begin( ), prefix.end( ), payload.bytes.begin( ) );

		std::size_t offset = prefix.size( ) + profile.packet_offsets_per_message;
		payload.bytes[ offset++ ] = 0x11;
		for ( std::size_t byte = 0; byte < sizeof( xuid ); ++byte )
			payload.bytes[ offset++ ] = static_cast< std::uint8_t >( xuid >> ( byte * 8u ) );

		payload.bytes[ offset++ ] = 0x18;
		do
		{
			std::uint8_t encoded = static_cast< std::uint8_t >( tick & 0x7Fu );
			tick >>= 7u;
			if ( tick )
				encoded |= 0x80u;
			payload.bytes[ offset++ ] = encoded;
		} while ( tick );

		payload.size = offset;
		return payload;
	}

	void destroy_message( void* message )
	{
		if ( message )
			INVOKE_VCALL( void, xorn( 0 ), message, xorn( 1u ) );
	}

	void* network_messages( )
	{
		const uintptr_t address = GetAddress( g_pNetworkMessages );
		return address ? *reinterpret_cast< void** >( address ) : nullptr;
	}
	
	void* make_voice_message( const voice_payload_t& payload )
	{
		void* messages = network_messages( );
		if ( !messages )
			return nullptr;

		void* record = INVOKE_VCALL( void*, xorn( 30 ), messages, 22 );
		if ( !record )
			return nullptr;

		auto* info = INVOKE_VCALL( std::uint8_t*, xorn( 12 ), messages, record );
		void* binding = info ? *reinterpret_cast< void** >( info + 0x08 ) : nullptr;
		if ( !binding )
			return nullptr;

		void* message = INVOKE_VCALL( void*, xorn( 6 ), binding );
		if ( !message )
			return nullptr;

		std::vector< std::uint8_t > framed;
		framed.reserve( payload.size + 6 );
		append_varint( static_cast< std::uint32_t >( payload.size ), framed );
		framed.insert( framed.end( ), payload.bytes.begin( ), payload.bytes.begin( ) + payload.size );
		const std::size_t logical_size = framed.size( );
		framed.resize( logical_size + 4 );

		bit_read_t reader = {
			framed.data( ),
			static_cast< std::int32_t >( logical_size ),
			static_cast< std::int32_t >( logical_size * 8 ),
			0,
			0,
			"Server Lagger",
			false,
			true,
			true,
			{ },
		};

		if ( !INVOKE_VCALL( bool, xorn( 4 ), messages, &reader, message ) || reader.overflow )
		{
			destroy_message( message );
			return nullptr;
		}

		return message;
	}

	void send_voice_payload( void* channel, const voice_payload_t& payload, const server_lagger_profile_t& profile, std::uint32_t datagrams )
	{
		void* prototype = make_voice_message( payload );
		if ( !prototype )
			return;

		bool transport_available = true;
		for ( std::uint32_t datagram = 0; datagram < datagrams && transport_available; ++datagram )
		{
			std::uint32_t batch_sent = 0;
			for ( ; batch_sent < profile.messages_per_datagram; ++batch_sent )
			{
				void* message = INVOKE_VCALL( void*, xorn( 4 ), prototype );
				if ( !message )
				{
					transport_available = false;
					break;
				}

				const bool accepted = INVOKE_VCALL( bool, xorn( 39 ), channel, message, static_cast< std::int8_t >( -1 ) );
				destroy_message( message );
				if ( !accepted )
				{
					transport_available = false;
					break;
				}
			}

			if ( batch_sent )
				INVOKE_VCALL( std::int32_t, xorn( 41 ), channel, xors( "Server Lagger" ), nullptr );
		}

		destroy_message( prototype );
	}
}

void misc::server_lagger( ) noexcept
{
	static voice_runtime_t runtime;
	if ( !config::misc_server_lagger )
	{
		runtime = { };
		return;
	}

	const uintptr_t network_client_address = GetAddress( NetworkGameClient );
	void* network_client = network_client_address ? *reinterpret_cast< void** >( network_client_address ) : nullptr;
	if ( !network_client )
	{
		runtime = { };
		return;
	}

	const int current_tick = INVOKE_VCALL( int, xorn( 5 ), network_client );
	if ( runtime.network_client == network_client && runtime.tick == current_tick )
		return;
	runtime = { network_client, current_tick };

	void* channel = INVOKE_VCALL( void*, xorn( 41 ), network_client, xorn( 0 ) );
	if ( !channel || !INVOKE_VCALL( bool, xorn( 47 ), channel ) )
		return;

	const server_lagger_profile_t& profile = selected_server_lagger_profile( );
	const int configured_amount = config::misc_server_lagger_amount;
	const std::uint32_t amount = static_cast< std::uint32_t >( std::clamp( configured_amount, 1, profile.maximum_datagrams_per_tick ) );
	const voice_payload_t payload = make_voice_payload( profile, g_voice_xuid_generator( ), static_cast< std::uint32_t >( current_tick ) );
	send_voice_payload( channel, payload, profile, amount );
}
