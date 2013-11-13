use strict;
use warnings;
use utf8;
use Test::More;
use Net::APNs::Extended;

my $apns = Net::APNs::Extended->new(cert => 'xxx');

subtest 'payload.aps must be hashref' =>sub {
    eval { $apns->_create_send_data('bf649785b6374018f3907deb2b502965802e19471e3d93c36749ca95f5770327', {}) };
    like $@, qr/aps parameter must be HASHREF/;
};

subtest '[command 2] success' => sub {
    $apns->command(2);
    my $chunk = $apns->_create_send_data('bf649785b6374018f3907deb2b502965802e19471e3d93c36749ca95f5770327' => {
        aps => { alert => 'メッセージ' },
    }, { identifier => 0, expiry => 0, priority => 0 });
    my ($command, $frame_data) = unpack 'c N/a*' => $chunk;
    my ($item_number1, $device_token, $item_number2, $json, $item_number3, $identifier_length, $identifier,
        $item_number4, $expiry_length, $expiry, $item_number5, $priority_length, $priority)
        = unpack 'c n/a* c n/a* c n N c n N c n N' => $frame_data;
    $device_token = unpack('H*', $device_token);

    is $command, 2;
    is $identifier, 0;
    is $expiry, 0;
    is $priority, 0;
    is $device_token, 'bf649785b6374018f3907deb2b502965802e19471e3d93c36749ca95f5770327';
    is_deeply $apns->json->decode($json), {
        aps => { alert => 'メッセージ' },
    };
};

subtest '[command 2] with extras' => sub {
    $apns->command(2);
    my $chunk = $apns->_create_send_data('bf649785b6374018f3907deb2b502965802e19471e3d93c36749ca95f5770327' => {
        aps => { alert => 'メッセージ' },
    }, { identifier => 12345, expiry => 56789, priority => 10 });
    my ($command, $frame_data) = unpack 'c N/a*' => $chunk;
    my ($item_number1, $device_token, $item_number2, $json, $item_number3, $identifier_length, $identifier,
        $item_number4, $expiry_length, $expiry, $item_number5, $priority_length, $priority)
        = unpack 'c n/a* c n/a* c n N c n N c n N' => $frame_data;
    $device_token = unpack('H*', $device_token);

    is $command, 2;
    is $identifier, 12345;
    is $expiry, 56789;
    is $priority, 10;
    is $device_token, 'bf649785b6374018f3907deb2b502965802e19471e3d93c36749ca95f5770327';
    is_deeply $apns->json->decode($json), {
        aps => { alert => 'メッセージ' },
    };
};

subtest '[command 1] success' => sub {
    $apns->command(1);
    my $chunk = $apns->_create_send_data('bf649785b6374018f3907deb2b502965802e19471e3d93c36749ca95f5770327' => {
        aps => { alert => 'メッセージ' },
    }, { identifier => 0, expiry => 0 });
    my ($command, $identifier, $expiry, $device_token, $json)
        = unpack 'c N N n/a* n/a*' => $chunk;
    $device_token = unpack('H*', $device_token);

    is $command, 1;
    is $identifier, 0;
    is $expiry, 0;
    is $device_token, 'bf649785b6374018f3907deb2b502965802e19471e3d93c36749ca95f5770327';
    is_deeply $apns->json->decode($json), {
        aps => { alert => 'メッセージ' },
    };
};

subtest '[command 1] with extras' => sub {
    $apns->command(1);
    my $chunk = $apns->_create_send_data('bf649785b6374018f3907deb2b502965802e19471e3d93c36749ca95f5770327' => {
        aps => { alert => 'メッセージ' },
    }, { identifier => 12345, expiry => 56789 });
    my ($command, $identifier, $expiry, $device_token, $json)
        = unpack 'c N N n/a* n/a*' => $chunk;
    $device_token = unpack('H*', $device_token);

    is $command, 1;
    is $identifier, 12345;
    is $expiry, 56789;
    is $device_token, 'bf649785b6374018f3907deb2b502965802e19471e3d93c36749ca95f5770327';
    is_deeply $apns->json->decode($json), {
        aps => { alert => 'メッセージ' },
    };
};

subtest '[command 1] trimed' => sub {
    $apns->command(1);
    my $chunk = $apns->_create_send_data('bf649785b6374018f3907deb2b502965802e19471e3d93c36749ca95f5770327' => {
        aps => { alert => 'メッセージ'x100 },
    }, { identifier => 12345, expiry => 56789 });
    my ($command, $identifier, $expiry, $device_token, $json)
        = unpack 'c N N n/a* n/a*' => $chunk;
    $device_token = unpack('H*', $device_token);

    is $command, 1;
    is $identifier, 12345;
    is $expiry, 56789;
    is $device_token, 'bf649785b6374018f3907deb2b502965802e19471e3d93c36749ca95f5770327';
    is_deeply $apns->json->decode($json), {
        aps => { alert => 'メッセージメッセージメッセージメッセージメッセージメッセージメッセージメッセージメッセージメッセージメッセージメッセージメッセージメッセージメッセージメッセ' },
    };
};

subtest '[command 1] badge to numify' => sub {
    $apns->command(1);
    my $chunk = $apns->_create_send_data('bf649785b6374018f3907deb2b502965802e19471e3d93c36749ca95f5770327' => {
        aps => { alert => 'メッセージ', badge => '100' },
    }, { identifier => 12345, expiry => 56789 });
    my ($command, $identifier, $expiry, $device_token, $json)
        = unpack 'c N N n/a* n/a*' => $chunk;
    $device_token = unpack('H*', $device_token);

    is $command, 1;
    is $identifier, 12345;
    is $expiry, 56789;
    is $device_token, 'bf649785b6374018f3907deb2b502965802e19471e3d93c36749ca95f5770327';
    is_deeply $apns->json->decode($json), {
        aps => { alert => 'メッセージ', badge => 100 },
    };
};

subtest '[command 1] trimd alter.body' => sub {
    $apns->command(1);
    my $chunk = $apns->_create_send_data('bf649785b6374018f3907deb2b502965802e19471e3d93c36749ca95f5770327' => {
        aps => { alert => { body => 'メッセージ'x100 }, badge => '100' },
    }, { identifier => 12345, expiry => 56789 });
    my ($command, $identifier, $expiry, $device_token, $json)
        = unpack 'c N N n/a* n/a*' => $chunk;
    $device_token = unpack('H*', $device_token);

    is $command, 1;
    is $identifier, 12345;
    is $expiry, 56789;
    is $device_token, 'bf649785b6374018f3907deb2b502965802e19471e3d93c36749ca95f5770327';
    is_deeply $apns->json->decode($json), {
        aps => {
            alert => {
                body => 'メッセージメッセージメッセージメッセージメッセージメッセージメッセージメッセージメッセージメッセージメッセージメッセージメッセージメッセージメ',
            },
            badge => 100,
        },
    };
};

subtest '[command 0] success' => sub {
    $apns->command(0);
    my $chunk = $apns->_create_send_data('bf649785b6374018f3907deb2b502965802e19471e3d93c36749ca95f5770327' => {
        aps => { alert => 'メッセージ' },
    }, { identifier => 0, expiry => 0 });
    my ($command, $device_token, $json) = unpack 'c n/a* n/a*' => $chunk;
    $device_token = unpack('H*', $device_token);

    is $command, 0;
    is $device_token, 'bf649785b6374018f3907deb2b502965802e19471e3d93c36749ca95f5770327';
    is_deeply $apns->json->decode($json), {
        aps => { alert => 'メッセージ' },
    };
};

done_testing;
