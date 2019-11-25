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
     * @var null|string
     */
    private $privateKeyContent;

    /**
     * @var null|string
     */
    private $privateKeyPath;

    /**
     * @var int time to live for token
     */
    private $ttl = 15552000;

    /**
     * ClientSecret constructor.
     *
     * @param string $clientId
     * @param string $teamId
     * @param string $keyId
     * @param string|null $certPath
     */
    public function __construct(string $clientId, string $teamId, string $keyId, string $certPath)
    {
        $this->clientId = $clientId;
        $this->teamId = $teamId;
        $this->keyId = $keyId;
        $this->privateKeyPath = $certPath;
    }

    /**
     * Sets a time to live in seconds
     *
     * @param int $ttl
     * @return $this
     */
    public function ttl(int $ttl): self
    {
        $this->ttl = $ttl;

        return $this;
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
        if ($this->privateKeyContent) {
            $content = $this->privateKeyContent;
        } elseif ($this->privateKeyPath) {
            $content = \file_get_contents($this->privateKeyPath);
        } else {
            throw new \InvalidArgumentException('Unable to find private key.');
        }

        return JWKFactory::createFromKey($content, null, [
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