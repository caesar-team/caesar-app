import { faker } from "@faker-js/faker";

export function createFakeUser(
  overrides?: Partial<{
    id: string;
    email: string;
    name: string;
  }>,
) {
  return {
    id: overrides?.id ?? faker.string.uuid(),
    email: overrides?.email ?? faker.internet.email(),
    name: overrides?.name ?? faker.person.fullName(),
  };
}

export function createFakeOrganization(
  overrides?: Partial<{
    id: string;
    name: string;
    slug: string;
  }>,
) {
  const name = overrides?.name ?? faker.company.name();
  return {
    id: overrides?.id ?? faker.string.uuid(),
    name,
    slug: overrides?.slug ?? faker.helpers.slugify(name).toLowerCase(),
  };
}

export function createFakeMember(
  organizationId: string,
  userId: string,
  role: "owner" | "admin" | "member" | "guest" = "member",
) {
  return {
    id: faker.string.uuid(),
    organizationId,
    userId,
    role,
  };
}
