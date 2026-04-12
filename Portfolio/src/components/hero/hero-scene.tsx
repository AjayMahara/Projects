"use client";

import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { Float, Stars } from "@react-three/drei";
import { useMemo, useRef } from "react";
import type { MutableRefObject } from "react";
import * as THREE from "three";

function CyberGlobe({
  mouse,
}: {
  mouse: MutableRefObject<{ x: number; y: number }>;
}) {
  const group = useRef<THREE.Group>(null);
  const mesh = useRef<THREE.Mesh>(null);

  useFrame((state, delta) => {
    if (!group.current || !mesh.current) return;
    const t = state.clock.elapsedTime;
    mesh.current.rotation.y += delta * 0.35;
    mesh.current.rotation.x = Math.sin(t * 0.2) * 0.08;
    const mx = mouse.current.x * 0.35;
    const my = mouse.current.y * 0.25;
    group.current.rotation.y = THREE.MathUtils.lerp(
      group.current.rotation.y,
      mx,
      0.04,
    );
    group.current.rotation.x = THREE.MathUtils.lerp(
      group.current.rotation.x,
      -my,
      0.04,
    );
  });

  return (
    <group ref={group}>
      <Float speed={1.2} rotationIntensity={0.15} floatIntensity={0.35}>
        <mesh ref={mesh}>
          <icosahedronGeometry args={[1.35, 2]} />
          <meshBasicMaterial
            color="#38bdf8"
            wireframe
            transparent
            opacity={0.85}
          />
        </mesh>
      </Float>
      <mesh scale={1.02}>
        <icosahedronGeometry args={[1.35, 2]} />
        <meshBasicMaterial
          color="#22f59b"
          wireframe
          transparent
          opacity={0.12}
        />
      </mesh>
    </group>
  );
}

function NodeRing() {
  const ref = useRef<THREE.Points>(null);
  const { mouse } = useThree();
  const geometry = useMemo(() => {
    const count = 220;
    const positions = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      const angle = (i / count) * Math.PI * 2;
      const r = 2.1 + (Math.random() - 0.5) * 0.25;
      positions[i * 3] = Math.cos(angle) * r;
      positions[i * 3 + 1] = (Math.random() - 0.5) * 0.6;
      positions[i * 3 + 2] = Math.sin(angle) * r;
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    return g;
  }, []);

  useFrame((_, delta) => {
    if (!ref.current) return;
    ref.current.rotation.y += delta * 0.08;
    ref.current.rotation.x += delta * 0.02 * mouse.y;
  });

  return (
    <points ref={ref} geometry={geometry}>
      <pointsMaterial
        size={0.035}
        color="#a78bfa"
        transparent
        opacity={0.9}
        depthWrite={false}
        sizeAttenuation
      />
    </points>
  );
}

function GridFloor() {
  const helper = useMemo(
    () => new THREE.GridHelper(14, 28, 0x38bdf8, 0x1e293b),
    [],
  );
  const ref = useRef<THREE.GridHelper>(null);
  useFrame((state) => {
    const obj = ref.current;
    if (!obj) return;
    const t = state.clock.elapsedTime;
    obj.position.set(0, -1.65, -2 + Math.sin(t * 0.15) * 0.05);
  });
  return <primitive ref={ref} object={helper} />;
}

function SceneContent({
  mouseRef,
}: {
  mouseRef: MutableRefObject<{ x: number; y: number }>;
}) {
  return (
    <>
      <color attach="background" args={["#05060a"]} />
      <ambientLight intensity={0.35} />
      <directionalLight position={[4, 6, 2]} intensity={0.8} color="#e2e8f0" />
      <Stars
        radius={80}
        depth={40}
        count={2800}
        factor={3}
        saturation={0}
        fade
        speed={0.35}
      />
      <CyberGlobe mouse={mouseRef} />
      <NodeRing />
      <GridFloor />
    </>
  );
}

export function HeroScene() {
  const mouseRef = useRef({ x: 0, y: 0 });

  return (
    <div
      className="absolute inset-0"
      onPointerMove={(e) => {
        const rect = (e.target as HTMLElement).getBoundingClientRect();
        const x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
        const y = ((e.clientY - rect.top) / rect.height) * 2 - 1;
        mouseRef.current = { x, y: -y };
      }}
      onPointerLeave={() => {
        mouseRef.current = { x: 0, y: 0 };
      }}
    >
      <Canvas
        camera={{ position: [0, 0.2, 5.2], fov: 42 }}
        dpr={[1, 2]}
        gl={{
          antialias: true,
          alpha: false,
          powerPreference: "high-performance",
        }}
        onCreated={({ gl }) => {
          gl.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        }}
      >
        <SceneContent mouseRef={mouseRef} />
      </Canvas>
      <div className="pointer-events-none absolute inset-0 bg-gradient-to-b from-transparent via-transparent to-white/80 dark:to-cyber-bg/95" />
    </div>
  );
}
