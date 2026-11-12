"""EC2 nova por repetição. Não chama a AWS.

A AMI de referência e a instância só existem depois de autorização explícita.
Este módulo recusa reutilização e recusa prepare.sh --apply como estado inicial.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class MethodologyError(RuntimeError):
    """O plano viola a regra de uma instância nova por script."""


@dataclass(frozen=True)
class ReferenceAmi:
    ami_id: str
    cve_id: str
    ubuntu_release: str
    package_name: str
    vulnerable_version: str
    fixed_version: str
    package_sha256: str
    scenario_id: str
    created_at_utc: str = ""
    private: bool = True

    def assert_record(self) -> None:
        if not self.ami_id.startswith("ami-") or self.ami_id == "ami-unused":
            raise MethodologyError("AMI de referência sem identificador ami-.")
        if not self.private:
            raise MethodologyError("A AMI de referência precisa ser privada.")
        if not self.package_sha256:
            raise MethodologyError("Hash do pacote vulnerável ausente.")
        if not self.vulnerable_version or not self.fixed_version:
            raise MethodologyError("Versões vulnerável e corrigida são obrigatórias.")


@dataclass
class InstanceLedger:
    """Controla instâncias abertas e já encerradas de um mesmo cenário."""

    expected_ami_id: str
    max_simultaneous: int = 1
    _open: dict[str, str] = field(default_factory=dict)
    _closed: set[str] = field(default_factory=set)

    def open_instance(self, instance_id: str, ami_id: str, repetition: str) -> None:
        if not instance_id.startswith("i-"):
            raise MethodologyError("instance_id inválido.")
        if ami_id != self.expected_ami_id:
            raise MethodologyError(
                f"A instância {instance_id} não usa a AMI de referência {self.expected_ami_id}."
            )
        if instance_id in self._open or instance_id in self._closed:
            raise MethodologyError(
                f"A instância {instance_id} já foi usada. Cada script exige uma EC2 nova."
            )
        if len(self._open) >= self.max_simultaneous:
            raise MethodologyError(
                "Limite de instâncias simultâneas atingido. "
                f"Máximo configurado: {self.max_simultaneous}."
            )
        self._open[instance_id] = repetition

    def close_instance(self, instance_id: str) -> None:
        if instance_id not in self._open:
            raise MethodologyError(f"A instância {instance_id} não está aberta nesta repetição.")
        del self._open[instance_id]
        self._closed.add(instance_id)

    @property
    def used_instance_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self._open) | self._closed))


def reject_restore_baseline(method: str) -> None:
    """prepare.sh --apply não substitui uma EC2 criada da AMI."""
    normalized = method.strip().lower()
    if "prepare" in normalized and "apply" in normalized:
        raise MethodologyError(
            "prepare.sh --apply não é o estado inicial de uma repetição nova. "
            "Crie uma EC2 a partir da AMI de referência."
        )


def reexecution_plan() -> list[str]:
    """Passos da reexecução. Nenhum deles cria recurso por si só."""
    return [
        "Manter a VPC, o NAT e a role já descritos no Terraform; não recriá-los a cada repetição.",
        "Preparar uma instância auxiliar, instalar o pacote vulnerável com hash conferido e gerar uma AMI privada.",
        "Destruir a instância auxiliar depois que a AMI existir.",
        "Para cada script original, criar uma EC2 nova dessa AMI, com instance_id inédito.",
        "Confirmar Ubuntu, versão do pacote e estado vulnerável antes de executar.",
        "Executar somente o remediation.sh daquela repetição.",
        "Verificar a versão com dpkg e um teste funcional do wget, sem exploração da CVE.",
        "Copiar as evidências para fora da instância e destruir somente essa EC2.",
        "Não chamar a API da OpenAI e não editar os scripts originais.",
    ]
