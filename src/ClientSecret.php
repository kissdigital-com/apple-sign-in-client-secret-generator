<?php

namespace Kissdigitalcom\AppleSignIn;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

/**
 * Apple Sign In Client Secret Generator
 */
class ClientSecret
{
    const DEFAULT_TTL = 15552000;

    /**
     * @var string
     */
    private $clientId;

    /**
     * @var string
     */
    private $teamId;

    /**
     * @var string
     */
    private $keyId;

    /**
     * @var string
     */
    private $privateKeyContent;

    /**
     * @var int time to live for token
     */
    private $ttl;

    /**
     * ClientSecret constructor.
     *
     * @param string $clientId
     * @param string $teamId
     * @param string $keyId
     * @param string $privateKeyContent
     * @param int|null $ttl
     */
    private function __construct(string $clientId, string $teamId, string $keyId, string $privateKeyContent, ?int $ttl = null)
    {
        $this->clientId = $clientId;
        $this->teamId = $teamId;
        $this->keyId = $keyId;
        $this->privateKeyContent = $privateKeyContent;
        $this->ttl = $ttl ?? self::DEFAULT_TTL;
    }

    /**
     * @param string $clientId
     * @param string $teamId
     * @param string $keyId
     * @param string $certPath
     * @return ClientSecret
     */
    public static function createFromPrivateKeyPath(string $clientId, string $teamId, string $keyId, string $certPath): self
    {
        $certContent = \file_get_contents($certPath);
        return new self($clientId, $teamId, $keyId, $certContent);
    }


    /**
     * @param string $clientId
     * @param string $teamId
     * @param string $keyId
     * @param string $certContent
     * @return ClientSecret
     */
    public static function createFromPrivateKeyContent(string $clientId, string $teamId, string $keyId, string $certContent): self
    {
        return new self($clientId, $teamId, $keyId, $certContent);
    }

    /**
     * Generate new token.
     *
     * @return string
     */
    public function generate(): string
    {
        $algorithmManager = new AlgorithmManager([new ES256()]);
        $jwsBuilder = new JWSBuilder($algorithmManager);
        $privateECKey = $this->generatePrivateECKey();
        $jws = $jwsBuilder
            ->create()
            ->withPayload(json_encode($this->getClaimsPayload()))
            ->addSignature($privateECKey, $this->getProtectedHeader($privateECKey))
            ->build();

        return (new CompactSerializer())->serialize($jws);
    }

    /**
     * Generate private EC key.
     *
     * @return JWK
     */
    private function generatePrivateECKey(): JWK
    {
        return JWKFactory::createFromKey($this->privateKeyContent, null, [
            'kid' => $this->keyId,
            'alg' => 'ES256',
        ]);
    }

    /**
     * Get protected header.
     *
     * @param JWK $privateECKey
     * @return array
     */
    private function getProtectedHeader(JWK $privateECKey): array
    {
        return [
            'alg' => 'ES256',
            'kid' => $privateECKey->get('kid'),
        ];
    }

    /**
     * Get claims payload.
     *
     * @return array
     */
    private function getClaimsPayload(): array
    {
        $time = time();

        return [
            'iss' => $this->teamId,
            'iat' => $time,
            'exp' => $time + $this->ttl,
            'aud' => 'https://appleid.apple.com',
            'sub' => $this->clientId,
        ];
    }
}
