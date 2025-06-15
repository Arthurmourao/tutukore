package OpenkoreToDiscord;

use strict;
use warnings;
use utf8;
use Encode qw(encode decode);
use Time::HiRes qw(time);
use Socket qw(PF_INET SOCK_STREAM pack_sockaddr_in inet_aton);
use Win32::Process qw(DETACHED_PROCESS CREATE_NO_WINDOW);
use Log;
use Globals;
use Settings;
use Plugins;
use Commands;
use FindBin qw($RealBin);

# Plugin registration
Plugins::register("OpenkoreToDiscord", "Sends exp report to Discord", \&on_unload);
my $hooks = Plugins::addHooks(
    ['start3', \&on_start],
    ['exp_gained', \&on_exp_gained],
    ['base_level_changed', \&on_base_level_changed],
    ['job_level_changed', \&on_job_level_changed],
    ['mainLoop_post', \&on_mainloop_post],
);

# Discord webhook URL
my $webhook_url = "YOUR_DISCORD_WEBHOOK_URL_HERE";

# Global variables
my $plugin_start_time = time;
my $session_base_exp_gained = 0;
my $session_job_exp_gained = 0;
my $base_levels_gained_session = 0;
my $job_levels_gained_session = 0;
my $exp_report_hook;
my $capturing_exp_report = 0;
my $exp_report_output = "";
my $last_report_time = 0; # Time of the last automatic report
my $report_interval = 10 * 60; # 10 minutes in seconds

# Unload function
sub on_unload {
    Plugins::delHooks($hooks);
}

# Start function
sub on_start {
    # Register command for manual report generation
    Commands::register(["discordreport", "Send a report to Discord", \&command_report]);

    # Initialize the last report time to the current time
    $last_report_time = time;

    # Create an embed for the plugin loaded notification
    my %embed = (
        title => "[Plugin] OpenkoreToDiscord Plugin Loaded",
        description => "Bot is now online and ready to report!\n\nThis plugin now uses Discord embeds for better formatting and readability.",
        color => 0x00FF00, # Green color
        timestamp => format_iso8601_time(time)
    );

    # Add fields to the embed
    my @fields = (
        {
            name => "Report Interval",
            value => sprintf("%.1f minutes", $report_interval / 60),
            inline => "true"
        },
        {
            name => "Commands",
            value => "`discordreport` - Send a report to Discord",
            inline => "true"
        }
    );

    # Only add fields if there are any
    if (scalar(@fields) > 0) {
        $embed{fields} = \@fields;
    }

    # Send notification that plugin has been loaded
    send_discord_with_embed(\%embed);
}

# Main loop hook for periodic reporting
sub on_mainloop_post {
    # Check if it's time to send a report (10 minutes have passed)
    my $current_time = time;
    if ($current_time - $last_report_time >= $report_interval) {
        # Generate and send the report
        my $report = generate_full_report();
        send_discord_embed($report);

        # Update the last report time
        $last_report_time = $current_time;
    }
}

# Experience gained hook
sub on_exp_gained {
    my (undef, $args) = @_;

    # Check if $args is a hash reference before trying to access its keys
    if (ref($args) eq 'HASH' && defined $args->{type} && defined $args->{exp}) {
        # This hook passes {type => type, exp => amount} where type is 'base' or 'job'
        if ($args->{type} eq 'base') {
            $session_base_exp_gained += $args->{exp};
        } elsif ($args->{type} eq 'job') {
            $session_job_exp_gained += $args->{exp};
        }
    }
}

# Base level changed hook
sub on_base_level_changed {
    my (undef, $args) = @_;

    # Check if $args is a hash reference before trying to access its keys
    if (ref($args) eq 'HASH' && defined $args->{level} && defined $args->{change}) {
        if ($args->{change} > 0) {
            $base_levels_gained_session += $args->{change};
        }
    }
}

# Job level changed hook
sub on_job_level_changed {
    my (undef, $args) = @_;

    # Check if $args is a hash reference before trying to access its keys
    if (ref($args) eq 'HASH' && defined $args->{level} && defined $args->{change}) {
        if ($args->{change} > 0) {
            $job_levels_gained_session += $args->{change};
        }
    }
}

# Command handler for manual report generation
sub command_report {
    my (undef, $args) = @_;

    # Generate and send the report
    my $report = generate_full_report();
    send_discord_embed($report);
}

# Global counter for message hook logging
my $exp_report_log_counter = 0;
# Flag to prevent recursive hook calls
my $inside_hook = 0;
# Maximum number of messages to capture
my $max_messages_to_capture = 100;
# Counter for captured messages
my $captured_messages_count = 0;

# Function to capture exp report output
sub exp_report_message_hook {
    my ($type, $domain, $level, $currentVerbosity, $message, $user_data, $near, $far) = @_;

    # Prevent recursive calls
    return if $inside_hook;
    $inside_hook = 1;

    # Increment counter
    $exp_report_log_counter++;

    # Safety check: stop capturing if we've captured too many messages
    if ($captured_messages_count > $max_messages_to_capture) {
        $capturing_exp_report = 0;
        $inside_hook = 0;
        return;
    }

    # Only capture messages when we're actively capturing
    if ($capturing_exp_report) {
        # Capture various types of messages that might be part of the exp report
        if ($type eq "message" || $type eq "list" || $type eq "info" || $type eq "success") {
            if (defined $message) {
                # Skip messages that are our own debug logs
                if ($message !~ /^\[Discord\]/) {
                    $exp_report_output .= $message . "\n";
                    $captured_messages_count++;
                }
            }
        }
    }

    # Reset the recursion prevention flag
    $inside_hook = 0;
}

# Function to capture the exp report
sub capture_exp_report {
    # Reset variables
    $exp_report_output = "";
    $captured_messages_count = 0;
    $exp_report_log_counter = 0;
    $inside_hook = 0;

    # Set the capturing flag
    $capturing_exp_report = 1;

    # Add a hook to capture messages
    my $hook_added = 0;
    eval {
        $exp_report_hook = Log::addHook(\&exp_report_message_hook);
        $hook_added = 1;
    };
    if ($@) {
        Log::message("[Discord] Error adding hook: $@\n");
        $capturing_exp_report = 0;
        return "";
    }

    # Set a timeout for the capture process
    my $start_time = time;
    my $timeout = 10; # 10 seconds timeout

    # Run the exp report command
    eval {
        Commands::run("exp report");
    };
    if ($@) {
        Log::message("[Discord] Error running 'exp report' command: $@\n");
    }

    # Wait a bit to ensure all messages are captured, but with timeout
    my $wait_time = 0;
    my $check_interval = 0.1; # Check every 0.1 seconds
    my $last_message_count = 0;
    my $no_new_messages_time = 0;
    my $no_new_messages_timeout = 2; # Wait 2 seconds after no new messages before considering it complete

    while ($wait_time < $timeout) {
        select(undef, undef, undef, $check_interval); # Sleep for a short time
        $wait_time += $check_interval;

        # Track message count changes
        if ($captured_messages_count > 0 && $captured_messages_count != $last_message_count) {
            $last_message_count = $captured_messages_count;
            $no_new_messages_time = 0; # Reset the no new messages timer
        } else {
            $no_new_messages_time += $check_interval;
        }

        # Break if we've captured messages and no new messages for a while
        if ($captured_messages_count > 0 && $no_new_messages_time >= $no_new_messages_timeout) {
            last;
        }

        # Check for timeout
        if (time - $start_time > $timeout) {
            last;
        }
    }

    # Always remove the hook and reset flags, even if an error occurred
    if ($hook_added) {
        eval {
            Log::delHook($exp_report_hook);
        };
        if ($@) {
            Log::message("[Discord] Error removing hook: $@\n");
        }
    }

    # Reset the capturing flag
    $capturing_exp_report = 0;
    $inside_hook = 0;

    return $exp_report_output;
}

# Function to generate the full report
sub generate_full_report {
    # Create a minimal report with just the exp report
    my $report = "";

    # Add minimal header with date and plugin start time for session duration calculation
    my $current_time = time;
    my $current_formatted_date_str = scalar localtime($current_time);
    $report .= "Date: $current_formatted_date_str\n";
    $report .= "Plugin_Start_Time: $plugin_start_time\n";

    # Add character name and level for reference
    if (defined $::char) {
        $report .= "Name: " . ($::char->{name} // 'N/A') . "\n";
        $report .= "Level: " . ($::char->{lv} // 'N/A') . "\n";
    }

    # Add the exp report output
    my $exp_report = capture_exp_report();

    if ($exp_report) {
        $report .= "Exp_Report:\n";
        $report .= $exp_report;
    } else {
        $report .= "No exp report data available.\n";
    }

    return $report;
}

# Function to format the report for Discord as an embed
sub format_discord_message {
    my ($report_text) = @_;

    if (!defined $report_text) {
        return "Error: No report data available.";
    }

    # Extract basic information without full parsing
    my $character_name = 'N/A';
    my $character_level = 'N/A';
    my $raw_exp_report = '';

    # Extract character name and level using simple regex
    if ($report_text =~ /Name: (.*?)\n/) {
        $character_name = $1;
    }

    if ($report_text =~ /Level: (.*?)\n/) {
        $character_level = $1;
    }

    # Extract the raw exp report
    if ($report_text =~ /Exp_Report:\n(.*?)(?:\Z)/s) {
        $raw_exp_report = $1;
        # Clean up any debug messages that might have been captured
        $raw_exp_report =~ s/\[Discord\].*?\n//g;
    }

    # Calculate session duration
    my $session_duration = time - $plugin_start_time;
    my $session_duration_hours = sprintf("%.1f", $session_duration / 3600);

    # Parse the exp report into sections
    my %sections = parse_exp_report($raw_exp_report);

    # Create the embed structure
    my $title = "Exp Report ($session_duration_hours" . "h)";
    # Ensure title is within 256 characters
    $title = substr($title, 0, 256) if length($title) > 256;

    my $description = "**Character:** $character_name\n**Level:** $character_level";
    # Ensure description is within 4096 characters
    $description = substr($description, 0, 4096) if length($description) > 4096;

    # Create fields for the embed
    my @fields = ();

    # Add general exp info field
    if ($sections{general}) {
        # Remove the first line from general section
        my $general_content = $sections{general};
        $general_content =~ s/^[^\n]*\n//;
        push @fields, {
            name => "General Info",
            value => "```\n" . $general_content . "\n```",
            inline => "false"
        };
    }

    # Add monster kill count field
    if ($sections{monsters}) {
        # Remove the first line from monsters section
        my $monsters_content = $sections{monsters};
        $monsters_content =~ s/^[^\n]*\n//;
        push @fields, {
            name => "Monstros Derrotados",
            value => "```\n" . $monsters_content . "\n```",
            inline => "false"
        };
    }

    # Add item change count field
    if ($sections{items}) {
        # Remove the first line from items section
        my $items_content = $sections{items};
        $items_content =~ s/^[^\n]*\n//;

        # Check if the items section exceeds 900 characters
        my $items_value = "```\n" . $items_content . "\n```";
        if (length($items_value) > 900) {
            # Use pagination for items if it exceeds 900 characters
            my @item_fields = create_paginated_item_fields($items_content);
            push @fields, @item_fields;
        } else {
            # Use a single field if it's under 900 characters
            push @fields, {
                name => "Variacao de Itens",
                value => $items_value,
                inline => "false"
            };
        }
    }

    # Ensure we don't exceed 25 fields
    if (scalar(@fields) > 25) {
        @fields = @fields[0..24];
    }

    # Create the embed JSON structure
    my %embed = (
        title => $title,
        description => $description,
        color => 43775, # Color specified in the issue description
        timestamp => format_iso8601_time(time)
    );

    # Only add fields if there are any
    if (scalar(@fields) > 0) {
        $embed{fields} = \@fields;
    }

    return \%embed;
}

# Function to parse the exp report into sections
sub parse_exp_report {
    my ($raw_exp_report) = @_;

    my %sections = (
        general => '',
        monsters => '',
        items => ''
    );

    return %sections if !$raw_exp_report;

    # Split the report into lines
    my @lines = split(/\n/, $raw_exp_report);

    # Current section being processed
    my $current_section = 'general';

    # Process each line
    foreach my $line (@lines) {
        # Check for section headers
        if ($line =~ /Contagem de Monstros Derrotados/ || $line =~ /Monster Killed Count/) {
            $current_section = 'monsters';
            $sections{$current_section} .= "$line\n";
        } elsif ($line =~ /Contagem de Variação de Itens/ || $line =~ /Item Change Count/) {
            # This is the items section header
            # Clear any previous content in the items section (in case it was incorrectly added to monsters)
            $sections{'items'} = '';
            $current_section = 'items';
            $sections{$current_section} .= "$line\n";
        } elsif ($line =~ /^-{20,}$/ && $current_section eq 'monsters') {
            # This is the separator line that marks the end of the monsters section
            # Add it to the monsters section and then switch to the items section
            $sections{$current_section} .= "$line\n";
            $current_section = 'items';
        } else {
            # Add the line to the current section
            $sections{$current_section} .= "$line\n";
        }
    }

    # Trim whitespace from each section
    foreach my $section (keys %sections) {
        $sections{$section} =~ s/^\s+|\s+$//g;
    }

    # Check if the items section is empty but the items section header is present in the monsters section
    if ($sections{items} eq '' && $sections{monsters} =~ /((?:-- Contagem de Variação de Itens ---|-- Item Change Count ---).*?)(?:\Z)/s) {
        # Extract the items section from the monsters section
        my $items_section = $1;

        # Remove the items section from the monsters section
        $sections{monsters} =~ s/\Q$items_section\E$//s;

        # Add the items section to the items section
        $sections{items} = $items_section;

        # Trim whitespace again
        $sections{monsters} =~ s/^\s+|\s+$//g;
        $sections{items} =~ s/^\s+|\s+$//g;
    }

    # Ensure the monsters section ends with the separator line
    if ($sections{monsters} !~ /\n-{20,}\s*$/s) {
        $sections{monsters} .= "\n" . "-" x 40;
    }

    # Ensure the items section starts with the items section header
    if ($sections{items} ne '' && $sections{items} !~ /^(?:-- Contagem de Variação de Itens ---|-- Item Change Count ---)/s) {
        $sections{items} = "" . $sections{items};
    }

    # Remove duplicate headers from the items section
    $sections{items} =~ s/\n-- Contagem de Varia(?:ção|..o) de Itens ---\n-- Contagem de Varia(?:ção|..o) de Itens ---/\n/g;

    # Ensure the items section ends with the separator line
    if ($sections{items} ne '' && $sections{items} !~ /-{20,}\s*$/s) {
        $sections{items} .= "\n" . "-" x 36;
    }

    return %sections;
}

# Function to create paginated item fields
sub create_paginated_item_fields {
    my ($items_text) = @_;

    my @fields = ();
    return @fields if !$items_text;

    # Split the items text into lines
    my @lines = split(/\n/, $items_text);

    # Extract the header (first line, which is now the second line since we removed the first line)
    my $header = "";
    if (scalar(@lines) >= 1) {
        $header = $lines[0] . "\n";
        # Remove the header from the lines array
        splice(@lines, 0, 1);
    }

    # Group items into chunks that fit within field value limit (900 chars)
    my $current_chunk = $header;
    my $chunk_number = 1;

    foreach my $line (@lines) {
        # Check if adding this line would exceed the limit (900 characters)
        my $new_length = length($current_chunk) + length($line) + 1;
        if ($new_length > 900) {
            # Create a field with the current chunk
            push @fields, {
                name => "Variacao de Itens (Parte $chunk_number)",
                value => "```\n" . $current_chunk . "\n```",
                inline => "false"
            };

            # Start a new chunk with the header
            $current_chunk = $header . $line . "\n";
            $chunk_number++;
        } else {
            # Add the line to the current chunk
            $current_chunk .= $line . "\n";
        }
    }

    # Add the last chunk if it's not empty
    if ($current_chunk ne $header) {
        push @fields, {
            name => "Variacao de Itens (Parte $chunk_number)",
            value => "```\n" . $current_chunk . "\n```",
            inline => "false"
        };
    }

    return @fields;
}

# Function to send a report as a Discord embed
sub send_discord_embed {
    my ($report_text) = @_;

    # Format the report as an embed
    my $embed = format_discord_message($report_text);

    if (!ref($embed)) {
        # If format_discord_message returned a string (error message), send it as plain text
        send_discord($embed);
        return;
    }

    # Ensure the embed is a hash reference
    if (ref($embed) ne 'HASH') {
        Log::message("[Discord] Error: Embed is not a hash reference\n");
        send_discord("Error: Embed is not a hash reference");
        return;
    }

    # Send the embed
    send_discord_with_embed($embed);
}

# Function to send a message to Discord
sub send_discord {
    my ($message) = @_;

    if (!defined $message) {
        Log::message("[Discord] Error: Message is undefined\n");
        return;
    }

    # Escape special characters
    $message =~ s/\\/\\\\/g;
    $message =~ s/"/\\"/g;
    $message =~ s/\n/\\n/g;
    $message =~ s/\r/\\r/g;

    # Create the JSON payload
    my $json = '{"content":"' . $message . '"}';

    # Send the JSON payload
    send_json_to_discord($json);
}

# Function to send a Discord embed
sub send_discord_with_embed {
    my ($embed) = @_;

    if (!defined $embed || !ref($embed)) {
        Log::message("[Discord] Error: Embed is undefined or not a reference\n");
        return;
    }

    # Convert the embed hash to JSON
    my $embed_json = embed_to_json($embed);

    # Create the final JSON payload with the embeds array
    # Ensure the embed_json is valid before adding it to the payload
    if ($embed_json && $embed_json ne '{}') {
        # Validate the JSON before sending
        if ($embed_json =~ /^{.*}$/) {
            # Create the final JSON payload with the embeds array
            my $json = '{"embeds":[' . $embed_json . ']}';

            # Send the JSON payload
            send_json_to_discord($json);
        } else {
            Log::message("[Discord] Error: Malformed embed JSON\n");
        }
    } else {
        Log::message("[Discord] Error: Invalid embed JSON\n");
    }
}

# Helper function to convert an embed hash to JSON
sub embed_to_json {
    my ($embed) = @_;

    # Start with the basic embed properties
    my $json = '{';

    # Track if we've added any properties
    my $has_properties = 0;

    # Add title if present
    if (defined $embed->{title}) {
        my $title = $embed->{title};
        # Ensure the title is decoded as UTF-8
        $title = decode('UTF-8', $title, Encode::FB_CROAK|Encode::LEAVE_SRC) unless Encode::is_utf8($title);
        $title =~ s/\\/\\\\/g;
        $title =~ s/"/\\"/g;
        $title =~ s/\n/\\n/g;
        $title =~ s/\r/\\r/g;
        $json .= '"title":"' . $title . '"';
        $has_properties = 1;
    }

    # Add description if present
    if (defined $embed->{description}) {
        if ($has_properties) {
            $json .= ',';
        }
        my $description = $embed->{description};
        # Ensure the description is decoded as UTF-8
        $description = decode('UTF-8', $description, Encode::FB_CROAK|Encode::LEAVE_SRC) unless Encode::is_utf8($description);
        $description =~ s/\\/\\\\/g;
        $description =~ s/"/\\"/g;
        $description =~ s/\n/\\n/g;
        $description =~ s/\r/\\r/g;
        $json .= '"description":"' . $description . '"';
        $has_properties = 1;
    }

    # Add color if present
    if (defined $embed->{color}) {
        if ($has_properties) {
            $json .= ',';
        }
        $json .= '"color":' . $embed->{color};
        $has_properties = 1;
    }

    # Add timestamp if present
    if (defined $embed->{timestamp}) {
        if ($has_properties) {
            $json .= ',';
        }
        my $timestamp = $embed->{timestamp};
        # Ensure the timestamp is decoded as UTF-8
        $timestamp = decode('UTF-8', $timestamp, Encode::FB_CROAK|Encode::LEAVE_SRC) unless Encode::is_utf8($timestamp);
        $timestamp =~ s/\\/\\\\/g;
        $timestamp =~ s/"/\\"/g;
        $json .= '"timestamp":"' . $timestamp . '"';
        $has_properties = 1;
    }

    # Process fields separately to avoid JSON formatting issues
    my $fields_json = "";
    my $has_valid_fields = 0;

    # Only process fields if they exist and are an array
    if (defined $embed->{fields} && ref($embed->{fields}) eq 'ARRAY' && scalar(@{$embed->{fields}}) > 0) {
        my @valid_fields = ();

        # First collect all valid fields
        foreach my $field (@{$embed->{fields}}) {
            # Skip invalid fields
            if (!defined $field || ref($field) ne 'HASH') {
                next;
            }

            # Ensure required properties exist
            my $valid_field = {};

            # Process name (required)
            if (defined $field->{name}) {
                my $name = $field->{name};
                # Ensure the name is decoded as UTF-8
                $name = decode('UTF-8', $name, Encode::FB_CROAK|Encode::LEAVE_SRC) unless Encode::is_utf8($name);
                $name =~ s/\\/\\\\/g;
                $name =~ s/"/\\"/g;
                $name =~ s/\n/\\n/g;
                $name =~ s/\r/\\r/g;
                $valid_field->{name} = $name;
            } else {
                # If name is missing, use a default
                $valid_field->{name} = "Field";
            }

            # Process value (required)
            if (defined $field->{value}) {
                my $value = $field->{value};
                # Ensure the value is decoded as UTF-8
                $value = decode('UTF-8', $value, Encode::FB_CROAK|Encode::LEAVE_SRC) unless Encode::is_utf8($value);
                $value =~ s/\\/\\\\/g;
                $value =~ s/"/\\"/g;
                $value =~ s/\n/\\n/g;
                $value =~ s/\r/\\r/g;
                $valid_field->{value} = $value;
            } else {
                # If value is missing, use a default
                $valid_field->{value} = "No content";
            }

            # Process inline property
            if (defined $field->{inline}) {
                $valid_field->{inline} = ($field->{inline} eq "true") ? "true" : "false";
            } else {
                $valid_field->{inline} = "false";
            }

            push @valid_fields, $valid_field;
        }

        # If we have valid fields, build the fields JSON
        if (scalar(@valid_fields) > 0) {
            $has_valid_fields = 1;
            $fields_json = '"fields":[';

            for (my $i = 0; $i < scalar(@valid_fields); $i++) {
                my $field = $valid_fields[$i];

                if ($i > 0) {
                    $fields_json .= ',';
                }

                $fields_json .= '{';
                $fields_json .= '"name":"' . $field->{name} . '",';
                $fields_json .= '"value":"' . $field->{value} . '",';
                $fields_json .= '"inline":' . $field->{inline};
                $fields_json .= '}';
            }

            $fields_json .= ']';
        }
    }

    # Add fields to the JSON if we have valid ones
    if ($has_valid_fields) {
        if ($has_properties) {
            $json .= ',';
        }
        $json .= $fields_json;
        $has_properties = 1;
    }

    # Remove trailing comma if present
    $json =~ s/,$//;

    # Close the JSON object properly
    $json .= '}';

    return $json;
}

# Function to send a JSON payload to Discord using an external Python script
sub send_json_to_discord {
    my ($json) = @_;
    Log::message("[Discord] Sending JSON payload to Discord using Python script\n");

    # Path to the Python script
    my $script_path = "$RealBin/plugins/OpenkoreToDiscord/discord_webhook.py";

    # Ensure the JSON is UTF-8 encoded and escape it for command line
    my $escaped_json = $json;
    # Ensure the JSON is decoded as UTF-8 first (if it's not already)
    $escaped_json = decode('UTF-8', $escaped_json, Encode::FB_CROAK|Encode::LEAVE_SRC) unless Encode::is_utf8($escaped_json);
    # Then encode it back to UTF-8 bytes for the command line
    $escaped_json = encode('UTF-8', $escaped_json);
    # Escape quotes for command line
    $escaped_json =~ s/"/\\"/g;

    # Create a temporary file for the response
    my $response_file = "discord_response.tmp";

    # Build the command to run the Python script silently
    my $python_cmd = "pythonw \"$script_path\" \"$webhook_url\" \"$escaped_json\" \"$response_file\"";

    # Run the Python script completely silently
    my $processObj;
    Win32::Process::Create(
        $processObj,
        "C:\\Windows\\System32\\cmd.exe",
        "cmd /c $python_cmd",
        0,
        CREATE_NO_WINDOW,
        "."
    ) or do {
        Log::message("[Discord] Error creating process: $^E\n");
        return;
    };

    # Wait for the process to complete
    $processObj->Wait(10000); # Wait up to 10 seconds

    # Parse the response
    my $status_code = 0;
    if (-e $response_file) {
        # Open the response file with UTF-8 encoding
        if (open(my $resp_fh, '<:encoding(UTF-8)', $response_file)) {
            my @response_lines = <$resp_fh>;
            close($resp_fh);

            # Look for status code and response in the output
            foreach my $line (@response_lines) {
                if ($line =~ /STATUS:(\d+)/) {
                    $status_code = $1;
                }
                if ($line =~ /RESPONSE:(.+)/) {
                    Log::message("[Discord] Response: $1\n");
                }
                if ($line =~ /ERROR:(.+)/) {
                    Log::message("[Discord] Error: $1\n");
                }
            }
        }

        # Delete the response file
        unlink($response_file);
    }

    # Log the result
    if ($status_code == 204) {
        Log::message("[Discord] Successfully sent to Discord (204 No Content)\n");
    } elsif ($status_code >= 200 && $status_code < 300) {
        Log::message("[Discord] Successfully sent to Discord (Status: $status_code)\n");
    } else {
        Log::message("[Discord] Failed to send to Discord (Status: $status_code)\n");
    }
}

# Function to parse the report text
sub parse_report_text {
    my ($report_text) = @_;

    if (!defined $report_text) {
        my %empty_data = (
            character => {},
            report_date_str => '',
            plugin_start_time => undef,
            exp_report => ''
        );
        return %empty_data;
    }

    my %parsed_data = (
        character => {},
        report_date_str => '',
        plugin_start_time => undef,
        exp_report => ''
    );

    # Parse date and plugin start time
    if ($report_text =~ /Date: (.*?)\n/) {
        $parsed_data{report_date_str} = $1;
    }

    if ($report_text =~ /Plugin_Start_Time: ([\d\.]+)/) {
        $parsed_data{plugin_start_time} = $1;
    }

    # Parse character name and level
    if ($report_text =~ /Name: (.*?)\nLevel: (.*?)(?:\n|$)/) {
        $parsed_data{character}{name} = $1;
        $parsed_data{character}{level} = $2;
    }

    # Parse exp report
    if ($report_text =~ /Exp_Report:\n(.*?)(?:\n\n|\Z)/s) {
        $parsed_data{exp_report} = $1;
    }

    return %parsed_data;
}

# Helper function to format time in ISO 8601 format exactly as specified in the issue description
sub format_iso8601_time {
    my ($time) = @_;
    my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = gmtime($time);
    return sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ", $year + 1900, $mon + 1, $mday, $hour, $min, $sec);
}


1;
